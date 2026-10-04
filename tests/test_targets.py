import unittest
from targets import expand_targets

class TargetTests(unittest.TestCase):
    def test_single_ip(self):
        targets = expand_targets(['192.0.2.10'])
        self.assertEqual([t.address for t in targets], ['192.0.2.10'])

    def test_small_cidr(self):
        targets = expand_targets(['192.0.2.0/30'])
        self.assertEqual([t.address for t in targets], ['192.0.2.1', '192.0.2.2'])

    def test_multiple_targets(self):
        targets = expand_targets(['192.0.2.10,192.0.2.11'])
        self.assertEqual({t.address for t in targets}, {'192.0.2.10', '192.0.2.11'})

if __name__ == '__main__':
    unittest.main()
