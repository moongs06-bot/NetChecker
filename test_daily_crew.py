import asyncio,copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from daily_crew import validate_result,review_daily,compact_evidence
class DailyCrewTests(unittest.TestCase):
 def setUp(self):
  self.original={'findings':[{'device':'pc-test','priority':'medium','observation':'CPU 고사용','explanation':'확인 필요','next_action':'프로세스 확인','evidence_ids':['observation:pc-test']}],'evidence':{'observation:pc-test':{'current':{'samples':60}},'expected:pc-test':{}},'trace':[]}
  self.result={'analysis':{'items':[{'candidate_id':0,'interpretation':'확인 필요'}]},'review':{'summary':'확인이 필요합니다.','items':[{'candidate_id':0,'verdict':'needs_check','priority':'medium','observation':'CPU 고사용이 관측됐습니다.','reason':'지속 여부 확인이 필요합니다.','next_action':'실행 프로그램을 확인해 주세요.','evidence_ids':['observation:pc-test']}]},'priority':{'candidate_ids':[0]}}
 def test_large_evidence_compaction(self):
  raw={'observation:pc-'+str(i):{'current':{'samples':600,'covered_seconds':36000,'max_cpu':95,'hourly_tx':{'8':123},'recent_intervals':[{'ts':'2026-10-02T00:00:00Z','tx_bytes':123456,'rx_bytes':789012,'extra':'x'*100} for _ in range(120)]},'baseline_days':0} for i in range(12)}
  before=copy.deepcopy(raw);compact=compact_evidence(raw)
  self.assertGreater(len(json.dumps(raw)),180000);self.assertLess(len(json.dumps(compact)),180000);self.assertEqual(raw,before)
  value=compact['observation:pc-0'];self.assertEqual(value['current']['samples'],600);self.assertEqual(value['baseline_days'],0);self.assertEqual(value['current']['interval_detail_scope']['omitted_samples'],120)
 def test_verified_list(self):
  findings,checks=validate_result(self.result,self.original);self.assertEqual(checks[0]['rank'],1);self.assertEqual(findings[0]['verification'],'needs_check')
 def test_foreign_evidence_rejected(self):
  self.result['review']['items'][0]['evidence_ids']=['observation:other']
  with self.assertRaises(ValueError):validate_result(self.result,self.original)
 def test_excluded_cannot_reappear(self):
  self.result['review']['items'][0]['verdict']='excluded'
  with self.assertRaises(ValueError):validate_result(self.result,self.original)
 def test_duplicate_priority_rejected(self):
  self.result['priority']['candidate_ids']=[0,0]
  with self.assertRaises(ValueError):validate_result(self.result,self.original)
 def test_missing_candidate_rejected(self):
  self.result['review']['items']=[]
  with self.assertRaises(ValueError):validate_result(self.result,self.original)
 def test_empty_candidates(self):
  result={'analysis':{'items':[]},'review':{'summary':'근거가 없습니다.','items':[]},'priority':{'candidate_ids':[]}}
  self.assertEqual(validate_result(result,{'findings':[]}),([],[]))
 def test_unavailable_worker_is_not_success(self):
  value=asyncio.run(review_daily({'openai_key':'test','crewai_python':'nonexistent-python-for-test'},copy.deepcopy(self.original),'2026-10-02'))
  self.assertEqual(value['daily_crew']['status'],'failed');self.assertEqual(value['priority_checks'],[]);self.assertEqual(value['trace'][-1]['status'],'failed')
 def test_no_network_hook(self):
  source=Path(__file__).with_name('server.py').read_text(encoding='utf-8')
  self.assertIn("if kind=='daily' and output.get('mode')!='no_data':",source)
if __name__=='__main__':unittest.main()
