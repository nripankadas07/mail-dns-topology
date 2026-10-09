import copy
import json
import unittest
from pathlib import Path
import mail_dns_topology as m


class Tests(unittest.TestCase):
    def setUp(self):self.s=json.loads(Path('snapshot.json').read_text())
    def codes(self):return {x['code'] for x in m.audit(self.s)['findings']}
    def test_valid(self):self.assertEqual(self.codes(),set())
    def test_fragment_inside_version(self):
        self.s['records'][1]['chunks']=['v=sp','f1 -all']
        self.assertFalse(self.codes())
    def test_separate_records_not_joined(self):
        self.s['records'].append(copy.deepcopy(self.s['records'][0]))
        self.assertIn('spf_record_count',self.codes())
    def test_missing_dependency(self):
        self.s['records'].pop(1)
        self.assertIn('spf_record_count',self.codes())
    def test_cycle(self):
        self.s['records'][1]['chunks']=['v=spf1 redirect=example.test']
        self.assertIn('spf_cycle',self.codes())
    def test_mx_missing_address(self):
        self.s['records'].pop()
        self.assertIn('mx_address_missing',self.codes())
    def test_dkim_revoked(self):
        self.s['records'][3]['chunks']=['v=DKIM1; p=']
        self.assertIn('dkim_key_missing_or_revoked',self.codes())
    def test_dmarc_policy(self):
        self.s['records'][2]['chunks']=['v=DMARC1; p=accept']
        self.assertIn('dmarc_policy',self.codes())
    def test_unsupported_not_green(self):
        self.s['records'][0]['chunks']=['v=spf1 a mx -all']
        self.assertIn('unsupported_spf_term',self.codes())
    def test_empty_txt(self):
        self.s['records'].append({'name':'example.test','type':'TXT','chunks':['']})
        self.assertFalse(self.codes())
    def test_family(self):
        self.s['records'][-1]['address']='::1'
        with self.assertRaises(ValueError):m.audit(self.s)
    def test_boolean_priority(self):
        self.s['records'][4]['priority']=True
        with self.assertRaises(ValueError):m.audit(self.s)
    def test_duplicate_tag(self):
        self.s['records'][2]['chunks']=['v=DMARC1; p=none; p=reject']
        with self.assertRaises(ValueError):m.audit(self.s)
    def test_case_trailing_dot(self):
        self.s['domain']='EXAMPLE.TEST.'
        self.assertFalse(self.codes())


if __name__=='__main__':unittest.main()
