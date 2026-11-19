import unittest
from detector import analyse_email

class DetectorTests(unittest.TestCase):
    def test_empty_message(self):
        self.assertEqual(analyse_email(" ")["risk"], "Not analysed")
    def test_clean_message_is_low(self):
        result = analyse_email("Hello team, our meeting is scheduled for Monday at 10:00. Regards, Sam.")
        self.assertEqual(result["risk"], "Low")
        self.assertEqual(result["score"], 0)
    def test_credential_and_urgency_raise_score(self):
        result = analyse_email("URGENT: verify your password immediately or account will be suspended.")
        self.assertEqual(result["risk"], "High")
        self.assertGreaterEqual(result["score"], 50)
    def test_shortened_http_link_is_flagged(self):
        result = analyse_email("Click here now: http://bit.ly/example")
        self.assertTrue(any(item["category"] == "URL structure warning" for item in result["findings"]))
        self.assertTrue(result["urls"][0]["flags"])
    def test_score_is_capped(self):
        result = analyse_email(("urgent verify your password claim your prize click here dear customer " * 20) + " http://bit.ly/a")
        self.assertLessEqual(result["score"], 100)

if __name__ == "__main__":
    unittest.main(verbosity=2)
