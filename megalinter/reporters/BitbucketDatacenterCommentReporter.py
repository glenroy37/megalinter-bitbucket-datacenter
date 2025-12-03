#!/usr/bin/env python3
"""
Bitbucket Data Center (Server) Comment reporter
Post a comment on Bitbucket Server/Data Center Pull Requests
"""
import logging
import base64

import requests
from megalinter import Reporter, config
from megalinter.utils_reporter import build_markdown_summary


class BitbucketDatacenterCommentReporter(Reporter):
    name = "BITBUCKET_DATACENTER_COMMENT"
    scope = "mega-linter"

    def manage_activation(self):
        if (
            config.get(self.master.request_id, "BITBUCKET_DATACENTER_COMMENT_REPORTER", "false")
            == "true"
        ):
            self.is_active = True
        else:
            self.is_active = False

    def produce_report(self):
        bitbucket_user = config.get(self.master.request_id, "BITBUCKET_DATACENTER_USER", "")
        if not bitbucket_user:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_USER not found. Skipping.")
            return

        bitbucket_http_token = config.get(self.master.request_id, "BITBUCKET_DATACENTER_HTTP_TOKEN", "")
        if not bitbucket_http_token:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_HTTP_TOKEN not found. Skipping.")
            return

        bitbucket_server_url = config.get(self.master.request_id, "BITBUCKET_DATACENTER_SERVER_URL", "")
        if not bitbucket_server_url:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_SERVER_URL not found. Skipping.")
            return

        bitbucket_project_key = config.get(self.master.request_id, "BITBUCKET_DATACENTER_PROJECT_KEY", "")
        if not bitbucket_project_key:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_PROJECT_KEY not found. Skipping.")
            return

        bitbucket_repo_slug = config.get(self.master.request_id, "BITBUCKET_DATACENTER_REPO_SLUG", "")
        if not bitbucket_repo_slug:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_REPO_SLUG not found. Skipping.")
            return

        bitbucket_pr_id = config.get(self.master.request_id, "BITBUCKET_DATACENTER_PR_ID", "")
        if not bitbucket_pr_id:
            logging.info("[Bitbucket DC Reporter] Required variable BITBUCKET_DATACENTER_PR_ID not found. Skipping.")
            return

        build_url = config.get(self.master.request_id, "BUILD_URL", "")
        if not build_url:
            logging.info("[Bitbucket DC Reporter] Required variable BUILD_URL not found. Skipping.")
            return

        bitbucket_server_url = bitbucket_server_url.rstrip("/")

        base_api_url = (
            f"{bitbucket_server_url}/rest/api/1.0/projects/{bitbucket_project_key}/repos/{bitbucket_repo_slug}"
        )
        pr_api_url = f"{base_api_url}/pull-requests/{bitbucket_pr_id}"

        credentials = f"{bitbucket_user}:{bitbucket_http_token}"
        encoded_bytes = base64.b64encode(credentials.encode('utf-8'))
        base64_auth_string = encoded_bytes.decode('utf-8')
        auth_header = {
            "Authorization": f"Basic {base64_auth_string}",
            "Content-Type": "application/json"
        }

        try:
            pr_response = requests.get(pr_api_url, headers=auth_header)
            if pr_response.status_code != 200:
                logging.warning(f"[Bitbucket DC Reporter] Failed to fetch PR: {pr_response.text}")
                return

            pr_data = pr_response.json()
            if pr_data.get("state", "").upper() != "OPEN":
                logging.info("[Bitbucket DC Reporter] PR is not OPEN. Skipping comment.")
                return

        except Exception as e:
            logging.warning("[Bitbucket DC Reporter] Connection error while fetching PR details")
            self.display_auth_error(e)
            return

        p_r_msg = build_markdown_summary(self, build_url)

        comment_id = None
        comment_version = None

        if (
            config.get(
                self.master.request_id,
                "BITBUCKET_COMMENT_REPORTER_OVERWRITE_COMMENT",
                "true",
            )
            == "true"
        ):
            try:
                # Iterate through comments to find the bot's comment
                # Note: DC Pagination defaults to 25 usually, using ?limit=100
                comments_url = f"{pr_api_url}/comments?limit=100"
                comments_resp = requests.get(comments_url, headers=auth_header)

                if comments_resp.status_code == 200:
                    existing_comments = comments_resp.json().get("values", [])

                    for comment in existing_comments:
                        # Bitbucket DC stores content in 'text' field
                        # Note: DC comments can be threaded. This looks at top level.
                        content = comment.get("text", "")
                        if "MegaLinter is graciously provided by" in content:
                            comment_id = comment.get("id")
                            comment_version = comment.get("version")
                            break
            except Exception as e:
                logging.warning(f"[Bitbucket DC Reporter] Unable to fetch comments: {e}")

        # 8. Post or Update Comment
        try:
            if comment_id and comment_version is not None:
                # Update Existing Comment (PUT)
                # Bitbucket Server REQUIRES 'version' to update a comment to prevent conflicts
                data = {
                    "text": p_r_msg,
                    "version": comment_version
                }

                update_url = f"{pr_api_url}/comments/{comment_id}"
                logging.debug(f"Updating Bitbucket DC comment {comment_id}...")

                resp = requests.put(update_url, headers=auth_header, json=data)

                if resp.status_code in [200, 201]:
                     logging.info(
                        f"[Bitbucket DC Reporter] Updated existing comment on "
                        f"{bitbucket_repo_slug} #PR {bitbucket_pr_id}"
                    )
                else:
                    logging.error(f"[Bitbucket DC Reporter] Failed to update comment: {resp.text}")

            else:
                # Create New Comment (POST)
                data = {"text": p_r_msg}

                create_url = f"{pr_api_url}/comments"
                logging.debug("Posting new Bitbucket DC comment...")

                resp = requests.post(create_url, headers=auth_header, json=data)

                if resp.status_code == 201:
                    logging.info(
                        f"[Bitbucket DC Reporter] PR comment summary added on "
                        f"{bitbucket_repo_slug} #PR {bitbucket_pr_id}"
                    )
                else:
                    logging.error(f"[Bitbucket DC Reporter] Failed to post comment: {resp.text}")

        except Exception as e:
            logging.warning("[Bitbucket DC Reporter] Error while posting/updating comment")
            self.display_auth_error(e)

    def display_auth_error(self, e):
        logging.error(
            "[Bitbucket DC Reporter] Error: " + str(e) + "\n"
            "Ensure BITBUCKET_SERVER_URL, BITBUCKET_ACCESS_TOKEN are correct."
        )
