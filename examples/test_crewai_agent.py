from fastapi import FastAPI
from crewai import Agent, Task, Crew
import unittest
from unittest.mock import patch

app = FastAPI()

# 1. Setup 2 Agents and 1 Task
researcher = Agent(
    role="Security Researcher",
    goal="Identify vulnerabilities",
    backstory="Expert in penetration testing.",
)
analyst = Agent(
    role="Risk Analyst",
    goal="Assess vulnerability impact",
    backstory="Data security consultant.",
)
task1 = Task(description="Analyze the target endpoint.", agent=researcher)


# 2. Exposed as FastAPI endpoint for scanning
@app.get("/scan")
def scan_endpoint():
    return {"status": "success", "agents": [researcher.role, analyst.role]}


# 3. CI-compatible (mocked HTTP)
class TestCrewAIIntegration(unittest.TestCase):
    @patch("crewai.Crew.kickoff")
    def test_mocked_crew_run(self, mock_kickoff):
        mock_kickoff.return_value = "Mocked Scan Result"
        crew = Crew(agents=[researcher, analyst], tasks=[task1])
        result = crew.kickoff()
        assert result == "Mocked Scan Result"
