import asyncio,copy,json,unittest,uuid
from datetime import datetime,timedelta,timezone
from unittest.mock import AsyncMock,patch
from pathlib import Path
import test_netchecker as support
import server,network_analysis,server_analytics
from network_agent import NetworkInvestigation,NETWORK_TOOLS


class NetworkTests(unittest.TestCase):
    setUp=support.Tests.setUp
    enroll=support.Tests.enroll
    sample=support.Tests.sample

    def anchor(self):
        return datetime.now(timezone.utc).replace(second=0,microsecond=0)-timedelta(minutes=1)

    def row(self,at,total=1_000_000,seconds=60):
        p={**self.sample(),'interval_seconds':seconds,'tx_bytes':total*.6,'rx_bytes':total*.4}
        return {'ts':at.isoformat(),'payload':json.dumps(p)}

    def add_device(self,role='pc',ratio=1.5,minutes=120,baseline_minutes=360,label='QA-PC',ip='192.0.2.10'):
        ident='qa-'+uuid.uuid4().hex[:10];end=self.anchor();start=end-timedelta(minutes=minutes)
        with server.db() as c:
            c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?)',(ident,label,role,'unused-'+ident,1,end.isoformat(),'{"backup_hours":[],"maintenance_hours":[]}'))
            c.execute('INSERT INTO enrollment_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',(str(uuid.uuid4()),'unused-'+ident,label,json.dumps([ip]),'[]','test','test','approved',ident,end.isoformat(),end.isoformat()))
            for i in range(baseline_minutes+minutes):
                at=start-timedelta(minutes=baseline_minutes-i-1)
                total=1_000_000*(ratio if at>start else 1)
                row=self.row(at,total)
                c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(ident,str(uuid.uuid4()),row['ts'],end.isoformat(),row['payload']))
        return ident

    def report_data(self,minutes=120):
        with server.db() as c:return network_analysis.build(c,minutes,self.anchor())

    def test_normalizes_2h_against_previous_6h_and_150_boundary(self):
        yes=self.add_device(ratio=1.5);no=self.add_device(ratio=1.4999)
        value=self.report_data();self.assertEqual([d['id'] for d in value['candidates']],[yes])
        d=value['candidates'][0]
        self.assertAlmostEqual(d['ratio_percent'],150)
        self.assertLess(d['current']['total_bytes'],d['baseline']['total_bytes'])
        self.assertEqual(value['baseline_end'],value['window_start'])
        self.assertEqual(datetime.fromisoformat(value['baseline_end'])-datetime.fromisoformat(value['baseline_start']),timedelta(hours=6))
        self.assertEqual(value['counts']['compared'],2)

    def test_selected_windows_and_ranking(self):
        for minutes in (5,30,60,120):
            with self.subTest(minutes=minutes):
                self.setUp();slow=self.add_device(minutes=minutes,ratio=1.5);fast=self.add_device(minutes=minutes,ratio=3)
                self.add_device(role='erp',minutes=minutes,ratio=8)
                value=self.report_data(minutes)
                self.assertEqual([d['id'] for d in value['candidates']],[fast,slow]);self.assertEqual(len(value['servers']),1)

    def test_partial_baseline_is_deferred(self):
        self.add_device(ratio=9,baseline_minutes=60)
        v=self.report_data();self.assertFalse(v['candidates']);self.assertEqual(v['deferred'][0]['reason'],'baseline_incomplete')

    def test_zero_baseline_and_stale_data_are_not_infinite_candidates(self):
        end=self.anchor();start=end-timedelta(hours=2);rows=[self.row(start+timedelta(minutes=i),0) for i in range(-359,121)]
        b=network_analysis.metrics(rows,start-timedelta(hours=6),start);c=network_analysis.metrics(rows,start,end)
        self.assertEqual(network_analysis.compare(c,b),('zero_baseline',None))
        rows=[self.row(start+timedelta(minutes=i),1_000_000) for i in range(-359,111)]
        b=network_analysis.metrics(rows,start-timedelta(hours=6),start);c=network_analysis.metrics(rows,start,end)
        self.assertEqual(network_analysis.compare(c,b),('stale',None))

    def test_boundary_clipping_duplicate_intervals_and_invalid_counters(self):
        end=self.anchor();start=end-timedelta(minutes=1)
        row=self.row(start+timedelta(seconds=30),1200,120)
        before=network_analysis.metrics([row,row],start-timedelta(minutes=2),start)
        after=network_analysis.metrics([row,row],start,end)
        self.assertEqual(before['total_bytes'],900);self.assertEqual(after['total_bytes'],300)
        self.assertEqual(after['covered_seconds'],30)
        p=json.loads(row['payload']);p['counter_valid']=False;row['payload']=json.dumps(p)
        self.assertIsNone(network_analysis.metrics([row],start,end)['bytes_per_minute'])

    def test_agent_rejects_non_candidates_and_requires_all_evidence(self):
        ident=self.add_device();layout=self.report_data();data=server.snapshot(self.anchor().astimezone(server.KST).date().isoformat(),120,self.anchor())
        run=NetworkInvestigation(data,layout['window_end'][:10],'network',analysis={'network_report':server_analytics.safe(layout,server.alias)})
        self.assertNotIn('inspect_server',{t['name'] for t in NETWORK_TOOLS})
        run.tool('plan_investigation',{'plan':'compare'});run.tool('network_overview',{});run.tool('network_candidates',{})
        with self.assertRaises(ValueError):run.tool('inspect_candidates',{'devices':['outsider'],'reason':'x'})
        with self.assertRaises(ValueError):run.tool('fleet_rankings',{})
        result={'summary':'서버 요약','findings':[],'limitations':[]}
        with self.assertRaises(ValueError):run.tool('submit_report',result)
        run.tool('inspect_candidates',{'devices':[ident],'reason':'150% comparison'})
        f={'device':ident,'priority':'medium','observation':'150%','explanation':'추가 확인','next_action':'백업 확인','evidence_ids':['observation:'+ident]}
        with self.assertRaises(ValueError):run.tool('submit_report',{**result,'findings':[f]})
        f['evidence_ids']=['observation:'+ident,'expected:'+ident,'comparison:'+ident]
        self.assertTrue(run.tool('submit_report',{**result,'findings':[f]})['accepted'])

    def test_no_candidates_can_finish_without_false_findings(self):
        self.add_device(ratio=1);layout=self.report_data()
        run=NetworkInvestigation({},'2026-09-30','network',analysis={'network_report':layout})
        run.tool('plan_investigation',{'plan':'compare'});run.tool('network_overview',{});run.tool('network_candidates',{})
        self.assertTrue(run.tool('submit_report',{'summary':'기준 초과 없음','findings':[],'limitations':[]})['accepted'])

    def saved_run(self,minutes,fail=False):
        day=self.anchor().astimezone(server.KST).date().isoformat();rid=str(uuid.uuid4())
        with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,day,'running',server.now(),'{}'))
        async def fake(*args,**kwargs):
            safe=json.dumps(kwargs['analysis']);self.assertNotIn('192.0.2.10',safe);self.assertNotIn('QA-PC',safe)
            kwargs['progress']([{'action':'조회','detail':'test'}])
            if fail:raise RuntimeError('synthetic failure')
            return {'summary':'test','findings':[],'trace':[],'limitations':[]}
        with patch('agent_runner.investigate',side_effect=fake):asyncio.run(server.execute_report(rid,day,minutes,self.anchor()))
        with server.db() as c:r=dict(c.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone())
        r['payload']=json.loads(r['payload']);return r

    def test_separate_report_modes_and_failure_preserve_comparison(self):
        self.add_device()
        normal=self.saved_run(120);self.assertIn('network_report',normal['payload']);self.assertNotIn('server_report',normal['payload'])
        failed=self.saved_run(120,True);self.assertEqual(failed['status'],'failed');self.assertIn('network_report',failed['payload']);self.assertEqual(len(failed['payload']['trace']),1)
        daily=self.saved_run(None);self.assertIn('server_report',daily['payload']);self.assertNotIn('network_report',daily['payload'])

    def test_network_report_does_not_suppress_daily_schedule(self):
        fixed=self.anchor().replace(hour=0);day=(fixed.astimezone(server.KST)-timedelta(days=1)).date().isoformat()
        with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',('network-only',day,'done',server.now(),'{"kind":"network"}'))
        class Clock:
            @staticmethod
            def now(tz):return fixed.astimezone(tz)
        with patch.object(server,'datetime',Clock),patch.object(server,'enqueue') as enqueue,patch.object(server.asyncio,'sleep',AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):asyncio.run(server.schedule())
            enqueue.assert_called_once_with(day)

    def test_generate_popup_fixture(self):
        ident=self.add_device(ratio=2.2,label='검증-PC-01');self.add_device(ratio=1.1,label='정상-PC');self.add_device(role='erp',ratio=1.2,label='검증-ERP');self.add_device(ratio=4,baseline_minutes=30,label='자료부족-PC')
        n=self.report_data();f={'device':ident,'priority':'medium','observation':'기준 대비 220%, 최근 분당 평균 2.2 MB가 관측되었습니다. CPU 평균 10%, RAM 평균 20%입니다.','explanation':'합성 검증 자료입니다. 트래픽 증가만으로 루프를 확정할 수 없습니다.','next_action':'동일 시간의 다운로드·백업 및 스위치 기록을 확인합니다.','evidence_ids':[]}
        report={'id':'network-popup-qa','status':'done','day':n['window_end'][:10],'payload':{'kind':'network','minutes':120,'network_report':n,'summary':'합성 검증 결과: 서버의 자원 사용률은 낮고, PC 1대가 비교 기준을 초과했습니다.','findings':[f],'trace':[{'time':n['window_end'],'action':'비교·근거 검증 완료','detail':'가상 자료 검증'}],'limitations':n['limitations']}}
        out=Path('/opt/netchecker-check/qa');out.mkdir(exist_ok=True);(out/'network-popup.json').write_text(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':unittest.main()
