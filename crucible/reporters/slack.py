import logging
from typing import Any

import httpx

from crucible.models import Grade, ScanResult

logger = logging.getLogger(__name__)


class SlackReporter:
    def _get_color(self, grade: Grade) -> str:
        if grade in (Grade.A, Grade.B):
            return "#2EB67D"  # Green
        elif grade == Grade.C:
            return "#ECB22E"  # Orange
        else:
            return "#E01E5A"  # Red

    def build_message(self, result: ScanResult) -> dict[str, Any]:
        color = self._get_color(result.grade)

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Crucible Security Scan: {result.target.name}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Target:*\n{result.target.url}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Grade:*\n{result.grade.value} ({result.overall_score:.0f}/100)",
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Critical Findings:*\n{result.critical_count}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*High Findings:*\n{result.high_count}",
                                },
                            ],
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Scan ID: `{result.id}` | Duration: {result.duration_seconds:.1f}s",
                                }
                            ],
                        },
                    ],
                }
            ]
        }

    async def send(self, webhook_url: str, result: ScanResult) -> None:
        payload = self.build_message(result)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload, timeout=10.0)
                response.raise_for_status()
        except Exception as e:
            # Log the warning but do not raise to prevent failing the overall scan
            logger.warning(f"Failed to send Slack notification: {e}")
