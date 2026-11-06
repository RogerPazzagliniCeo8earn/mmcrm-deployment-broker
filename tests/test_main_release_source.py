from __future__ import annotations
import copy
import unittest
from ops.broker.main_release_source import APP_COMMIT, APP_TREE, REPO, Reject, validate_main_source

def valid():
    branch={"name":"main","commit":{"sha":APP_COMMIT}}
    commit={"sha":APP_COMMIT,"commit":{"tree":{"sha":APP_TREE}},
            "html_url":f"https://github.com/{REPO}/commit/{APP_COMMIT}"}
    statuses={"state":"pending","statuses":[]}
    checks={"total_count":1,"check_runs":[{
        "name":"Linux install, regression tests, typecheck and builds",
        "head_sha":APP_COMMIT,"status":"completed","conclusion":"success"}]}
    run={"id":42214127219,"head_sha":APP_COMMIT,"head_branch":"main",
         "event":"push","status":"completed","conclusion":"success",
         "path":".github/workflows/mmcrm-linux-checks.yml",
         "name":"MMcrm Linux security checks","repository":{"full_name":REPO}}
    return branch,commit,statuses,checks,run

class MainReleaseSourceTests(unittest.TestCase):
    def test_integrated_main_with_successful_ci(self):
        validate_main_source(*valid())

    def test_old_pr20_release_is_not_eligible(self):
        inputs=list(valid())
        inputs[0]["commit"]["sha"]="df195e6da70206bdd2e690507558a63eaa3705e5"
        with self.assertRaises(Reject): validate_main_source(*inputs)

    def test_requires_real_main_head_and_provenance(self):
        for index, key, value in (
            (0,"name","feature"),(0,"commit",{"sha":"0"*40}),
            (1,"sha","0"*40),(1,"html_url","https://github.com/another/repo/commit/"+APP_COMMIT),
            (4,"head_branch","feature"),(4,"event","workflow_dispatch"),
            (4,"path",".github/workflows/unrelated.yml"),
            (4,"name","Unrelated tests"),(4,"repository",{"full_name":"attacker/repo"}),
            (4,"conclusion","failure"),
        ):
            with self.subTest(field=(index,key)):
                data=list(copy.deepcopy(valid()))
                data[index][key]=value
                with self.assertRaises(Reject): validate_main_source(*data)

    def test_fail_closed_on_partial_or_unsuccessful_checks(self):
        mutations=[
            lambda c:c.update(total_count=2),
            lambda c:c["check_runs"][0].update(conclusion="failure"),
            lambda c:c["check_runs"][0].update(head_sha="0"*40),
            lambda c:c.update(check_runs=[],total_count=0),
        ]
        for mutate in mutations:
            with self.subTest(mutation=str(mutate)):
                data=list(copy.deepcopy(valid()))
                mutate(data[3])
                with self.assertRaises(Reject): validate_main_source(*data)

    def test_any_real_legacy_failure_blocks(self):
        data=list(valid())
        data[2]={"state":"failure","statuses":[{"state":"failure"}]}
        with self.assertRaises(Reject): validate_main_source(*data)

    def test_run_cannot_be_pending_or_from_wrong_commit(self):
        for field,val in (("status","in_progress"),("head_sha","0"*40),("id",0)):
            data=list(copy.deepcopy(valid()))
            data[4][field]=val
            with self.assertRaises(Reject): validate_main_source(*data)

if __name__=="__main__":
    unittest.main()
