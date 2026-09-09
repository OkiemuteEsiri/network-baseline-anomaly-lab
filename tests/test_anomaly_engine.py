import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).parents[1] / "src" / "anomaly_engine.py"
spec = importlib.util.spec_from_file_location("anomaly_engine", MODULE)
anomaly_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(anomaly_engine)

BASELINE={"known_external_destinations":["203.0.113.20"],"communications":{"app->db":{"ports":[5432],"avg_connections":10,"zone_paths":[["app","data"]]}}}

class Tests(unittest.TestCase):
    def test_known_flow_is_clean(self):
        flow={"source":"app","destination":"db","port":5432,"connections":11,"source_zone":"app","destination_zone":"data","destination_type":"internal"}
        self.assertEqual(anomaly_engine.detect(BASELINE,[flow]),[])
    def test_new_pair_detected(self):
        flow={"source":"user","destination":"db","port":5432,"connections":1,"destination_type":"internal"}
        self.assertTrue(any(x.rule_id=="NET-01" for x in anomaly_engine.detect(BASELINE,[flow])))
    def test_admin_port_is_high(self):
        flow={"source":"app","destination":"db","port":3389,"connections":1,"source_zone":"app","destination_zone":"data","destination_type":"internal"}
        self.assertTrue(any(x.rule_id=="NET-02" and x.severity=="high" for x in anomaly_engine.detect(BASELINE,[flow])))
    def test_new_external_detected(self):
        flow={"source":"app","destination":"198.51.100.44","port":443,"connections":1,"destination_type":"external"}
        self.assertTrue(any(x.rule_id=="NET-05" for x in anomaly_engine.detect(BASELINE,[flow])))
    def test_score_cap(self):
        a=anomaly_engine.Anomaly("x","critical","a","b","c")
        self.assertEqual(anomaly_engine.score([a]*20),100)

if __name__=="__main__": unittest.main()
