import copy,json,unittest,uuid
from pathlib import Path
import test_netchecker as support
import server
from display_utils import visible_ipv4,sanitize

class DisplayTests(unittest.TestCase):
    setUp=support.Tests.setUp
    registration=support.Tests.registration

    def test_display_only_ipv4_and_no_mac_without_mutating_source(self):
        source={'ips':['169.254.1.2','169.10.2.3','192.0.2.10','fe80::1','fde1::1','::ffff:192.0.2.4'],'macs':['00:11:22:33:44:55'],'nested':{'ip':'169.254.1.2'},'evidence':{'ips':['ip-pseudonym'],'ip':'ip-pseudonym'}}
        old=copy.deepcopy(source);value=sanitize(source)
        self.assertEqual(value['ips'],['192.0.2.10','192.0.2.4']);self.assertNotIn('macs',value)
        self.assertNotIn('169.',json.dumps(value));self.assertNotIn('fe80',json.dumps(value));self.assertEqual(value['evidence']['ips'],['ip-pseudonym']);self.assertEqual(source,old)

    def test_status_and_saved_reports_use_display_policy(self):
        body=self.registration();body['ips']=['169.254.1.2','192.0.2.10','fe80::1']
        self.client.post('/api/enrollment/request',json=body)
        status=self.client.get('/api/status',auth=self.auth).json()
        self.assertEqual(json.loads(status['pending'][0]['ips']),['192.0.2.10'])
        with server.db() as c:
            original=c.execute('SELECT ips FROM enrollment_requests').fetchone()['ips'];self.assertIn('169.254.1.2',original)
            c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',('ip-test','2026-09-30','done',server.now(),json.dumps({'server_report':{'ips':body['ips'],'macs':body['macs']}})))
        payload=self.client.get('/api/reports/ip-test',auth=self.auth).json()['payload']
        self.assertEqual(payload['server_report']['ips'],['192.0.2.10']);self.assertNotIn('macs',payload['server_report'])

    def test_pdf_title_and_old_report_addresses(self):
        fixture=Path('/opt/netchecker-check/qa/report.json')
        report=json.loads(fixture.read_text())
        # Keep the display fixture small; it represents old stored data with extra addresses.
        layout=report['payload']['server_report'];layout['pcs']=layout['pcs'][:2];layout['counts'].update(registered=3,pcs=2,collected=3)
        for d in layout['servers']+layout['pcs']:d['ips']+=['169.254.1.2','fe80::1','fde1::1']
        from pdf_report import build_report
        out=Path('/opt/netchecker-network-check/qa');out.mkdir(exist_ok=True)
        (out/'network-environment-report.pdf').write_bytes(build_report(report))
        self.assertTrue((out/'network-environment-report.pdf').read_bytes().startswith(b'%PDF-'))

if __name__=='__main__':unittest.main()
