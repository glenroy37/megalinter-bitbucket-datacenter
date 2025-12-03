#!/usr/bin/env python3
"""
Bitbucket Comment reporter
Post a comment on Bitbucket Merge Requests
"""
import logging
import urllib.parse
import base64

import requests
from megalinter import Reporter, config
from megalinter.utils_reporter import build_markdown_summary


class BitbucketCommentReporter(Reporter):
    name = "BITBUCKET_COMMENT"
    scope = "mega-linter"


    def manage_activation(self):
        if not config.exists(self.master.request_id, "BITBUCKET_REPO_FULL_NAME") and not config.exists(self.master.request_id, "BITBUCKET_DATACENTER_URL"):
            self.is_active = False
        elif (
            config.get(self.master.request_id, "BITBUCKET_COMMENT_REPORTER", "true")
            == "true"
        ):
            self.is_active = True
        else:
            self.is_active = False

    def produce_report(self):
        BITBUCKET_API = "https://api.bitbucket.org/2.0"
        BITBUCKET_CLOUD = True

        # Post comment on Bitbucket pull request
        bitbucket_server_url = config.get(self.master.request_id, "BITBUCKET_DATACENTER_URL", "")
        if bitbucket_server_url != "":
            BITBUCKET_API = bitbucket_server_url + "/rest/api/1.0"
            BITBUCKET_CLOUD = False

        BITBUCKET_REPO_ACCESS_TOKEN = config.get(
            self.master.request_id, "BITBUCKET_REPO_ACCESS_TOKEN", ""
        )
        bitbucket_user = config.get(
            self.master.request_id, "BITBUCKET_DATACENTER_USER", ""
        )
        bitbucket_http_token = config.get(
            self.master.request_id, "BITBUCKET_DATACENTER_HTTP_TOKEN", ""
        )
        bitbucket_repo_slug = config.get(
            self.master.request_id, "BITBUCKET_DATACENTER_REPO_SLUG", ""
        )
        bitbucket_project_key = config.get(
            self.master.request_id, "BITBUCKET_DATACENTER_PROJECT_KEY", ""
        )
        build_url = config.get(
            self.master.request_id, "BUILD_URL", ""
        )
        bitbucket_repo_fullname = config.get(
            self.master.request_id, "BITBUCKET_REPO_FULL_NAME", ""
        )
        bitbucket_project_url = config.get(
            self.master.request_id, "BITBUCKET_GIT_HTTP_ORIGIN", ""
        )
        bitbucket_pipeline_job_number = config.get(
            self.master.request_id, "BITBUCKET_BUILD_NUMBER", ""
        )
        bitbucket_pr_id = config.get(self.master.request_id, "BITBUCKET_PR_ID", "")
        pipeline_step_run_uuid = config.get(
            self.master.request_id, "BITBUCKET_STEP_UUID", ""
        )

        if BITBUCKET_CLOUD:
            if (
                BITBUCKET_REPO_ACCESS_TOKEN == ""
                or bitbucket_repo_fullname == ""
                or bitbucket_project_url == ""
                or bitbucket_pipeline_job_number == ""
                or bitbucket_pr_id == ""
                or build_url == ""
            ):
                logging.info(
                    "[Bitbucket Comment Reporter] Required Bitbucket CI CD variables not found, so skipped post of PR "
                    "comment"
                )
                return
        else:
            if (
                bitbucket_user == ""
                or bitbucket_http_token == ""
                or bitbucket_project_key == ""
                or bitbucket_repo_slug
                or bitbucket_pipeline_job_number == ""
                or bitbucket_pr_id == ""
                or pipeline_step_run_uuid == ""
            ):
                logging.info(
                    "[Bitbucket Comment Reporter] Required Bitbucket CI CD variables not found, so skipped post of PR "
                    "comment"
                )
                return

        if BITBUCKET_CLOUD:
            pipeline_step_run_uuid = urllib.parse.quote(pipeline_step_run_uuid)
            pipeline_step_run_url = (
                f"{bitbucket_project_url}/pipelines/results/"
                f"{bitbucket_pipeline_job_number}/steps/{pipeline_step_run_uuid}"
            )

            p_r_msg = build_markdown_summary(self, pipeline_step_run_url)
            bitbucket_auth_header = {
                "Authorization": f"Bearer {BITBUCKET_REPO_ACCESS_TOKEN}"
            }
        else:
            credentials = f"{bitbucket_user}:{bitbucket_http_token}"
            encoded_bytes = base64.b64encode(credentials.encode('utf-8'))
            base64_auth_string = encoded_bytes.decode('utf-8')
            bitbucket_auth_header = {
                "Authorization": f"Basic {base64_auth_string}",
                "Content-Type": "application/json"
            }

        # To-Do: Ignore if PR is already merged
        try:
            if BITBUCKET_CLOUD:
                pr = requests.get(
                    f"{BITBUCKET_API}/repositories/{bitbucket_repo_fullname}/pullrequests/{bitbucket_pr_id}",
                    headers=bitbucket_auth_header,
                )
            else:
                pr = requests.get(
                    f"{BITBUCKET_API}/projects/{bitbucket_project_key}/repos/{bitbucket_repo_slug}/pull-requests/{bitbucket_pr_id}"
                )
            if pr.status_code != 200:
                pr.raise_for_status()
            pr_state = pr.json().get("state", "")

            if pr_state.lower() != "open":
                logging.info(
                    "[Bitbucket Comment Reporter] PR is not in OPEN state, skipped posting comment"
                )
                return
        except Exception as e:
            logging.warning("[Bitbucket Comment Reporter] Unable to get PR details")
            self.display_auth_error(e)
            return

        # List comments on pull request
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
                if BITBUCKET_CLOUD:
                    comments = requests.get(
                        f"{BITBUCKET_API}/repositories/{bitbucket_repo_fullname}/"
                        f"pullrequests/{bitbucket_pr_id}/comments?pagelen=100",
                        headers=bitbucket_auth_header,
                    )
                else:
                    comments_url = f"{BITBUCKET_API}/projects/{bitbucket_project_key}/repos/{bitbucket_repo_slug}/pull-requests/{bitbucket_pr_id}"
                    comments = requests.get(comments_url, headers=bitbucket_auth_header)
                if comments.status_code != 200:
                    pr.raise_for_status()
                existing_comments = comments.json().get("values", [])
            except Exception as e:
                logging.warning(
                    "[Bitbucket Comment Reporter] Unable to fetch existing comments on PR"
                    + str(e)
                )
                return

            # Check if there is already a MegaLinter comment
            for comment in existing_comments:
                if "MegaLinter is graciously provided by" in comment.get(
                    "content", {}
                ).get("raw", ""):
                    comment_id = comment.get("id", None)
                    if not BITBUCKET_CLOUD:
                        # Bitbucket Datacenter REQUIRES 'version' to update a comment to prevent conflicts
                        comment_version = comment.get("version")
                    break

        # Process comment
        try:
            if BITBUCKET_CLOUD:
                data = {"content": {"raw": p_r_msg}}
            elif comment_version is not None:
                data = {"text": p_r_msg, "version": comment_version}
            else:
                data = {"text": p_r_msg}
            if comment_id is not None:
                # Existing comment
                logging.debug(f"Updated Bitbucket comment: {p_r_msg}")
                logging.info(
                    f"[Bitbucket Comment Reporter] Updated existing comment summary "
                    f"on {bitbucket_repo_fullname} #PR {bitbucket_pr_id}"
                )
                if BITBUCKET_CLOUD:
                    request_url = f"{BITBUCKET_API}/repositories/{bitbucket_repo_fullname}/pullrequests/"
                    f"{bitbucket_pr_id}/comments/{comment_id}"
                else:
                    request_url = f"{BITBUCKET_API}/projects/{bitbucket_project_key}/repos/{bitbucket_repo_slug}/"
                    f"pull-requests/{bitbucket_pr_id}/comments/{comment_id}"

                requests.put(
                    request_url,
                    headers=bitbucket_auth_header,
                    json=data,
                )
            else:
                # New comment
                if BITBUCKET_CLOUD:
                    request_url = f"{BITBUCKET_API}/repositories/{bitbucket_repo_fullname}/pullrequests/"
                    f"{bitbucket_pr_id}/comments"
                else:
                    request_url = f"{BITBUCKET_API}/projects/{bitbucket_project_key}/repos/{bitbucket_repo_slug}/"
                    f"pull-requests/{bitbucket_pr_id}/comments/{comment_id}"
                requests.post(
                    request_url,
                    headers=bitbucket_auth_header,
                    json=data,
                )
                logging.info(
                    f"[Bitbucket Comment Reporter] PR comment summary added on {bitbucket_repo_fullname} "
                    f"#PR {bitbucket_pr_id}"
                )

        except Exception as e:
            logging.warning("[Bitbucket Comment Reporter] Error while posting comment")
            self.display_auth_error(e)

    def display_auth_error(self, e):
        logging.error(
            "[Bitbucket Comment Reporter] You may need to define a masked "
            "Bitbucket CI/CD variable BITBUCKET_REPO_ACCESS_TOKEN containing "
            "a access token with scope 'Pull-requests: write' "
            "(if already defined, your access token is probably invalid): " + str(e)
        )
