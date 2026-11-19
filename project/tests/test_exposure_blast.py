"""Exposure and blast radius are measured on the resource, not fixed per rule."""
from cra.evaluation import check_context
from cra.exposure_graph import graph_nodes, draw_exposure_graph
from cra.models import Resource
from cra.reporting import render_html
from cra.rules import evaluate
from cra.scoring import score_all


def res(type_, id_="r1", **data):
    return Resource(id=id_, type=type_, name=id_, data=data)


def finding(cfg, resource, rule_id):
    ev = evaluate([resource], cfg)
    score_all(ev.findings, cfg.scoring)
    return next(f for f in ev.findings if f.rule_id == rule_id)


# ---- S3: exposure depends on the other S3 settings ------------------------------------------------------
def test_public_acl_exposure_depends_on_block_public_access(cfg):
    base = dict(public_acl=True, encrypted=True, versioning=True)
    assert finding(cfg, res("s3_bucket", block_public=False, **base), "S3-001").exposure_level == 1.0
    assert finding(cfg, res("s3_bucket", block_public=True, **base), "S3-001").exposure_level == 0.0
    assert finding(cfg, res("s3_bucket", block_public=None, **base), "S3-001").exposure_level == 1.0   # unknown: careful


def test_missing_block_public_access_only_matters_if_something_is_public(cfg):
    base = dict(encrypted=True, versioning=True, block_public=False)
    assert finding(cfg, res("s3_bucket", public_acl=True, **base), "S3-004").exposure_level == 1.0
    assert finding(cfg, res("s3_bucket", public_acl=False, **base), "S3-004").exposure_level == 0.0
    assert finding(cfg, res("s3_bucket", public_acl=None, **base), "S3-004").exposure_level == 0.5


# ---- NET-001: an open security group is only exposed if it protects something with a public IP ------------
def test_security_group_exposure_levels(cfg):
    sg = lambda **kw: finding(cfg, res("security_group", open_ranges=[(22, 22)], **kw), "NET-001")
    assert sg(public_reach=True, dependents=["i-1"]).exposure_level == 1.0
    assert sg(public_reach=False, dependents=["eni-1"]).exposure_level == 0.5
    assert sg(public_reach=False, dependents=[]).exposure_level == 0.0
    assert sg().exposure_level == 1.0                       # could not check what it protects: assume reachable
    assert "public IP" in sg(public_reach=True, dependents=["i-1"]).exposure_reason


def test_exposure_scales_the_bonus(cfg):
    sg = lambda **kw: finding(cfg, res("security_group", open_ranges=[(22, 22)], **kw), "NET-001")
    full = sg(public_reach=True, dependents=["i-1"])
    part = sg(public_reach=False, dependents=["eni-1"])
    none = sg(public_reach=False, dependents=[])
    assert full.score_breakdown["exposure_bonus"] == 1.0
    assert part.score_breakdown["exposure_bonus"] == 0.5
    assert none.score_breakdown["exposure_bonus"] == 0.0
    assert full.score > part.score > none.score


# ---- blast radius is counted ----------------------------------------------------------------------------
def test_blast_radius_grows_with_dependents_and_is_capped(cfg):
    pol = lambda deps: finding(cfg, res("iam_policy", admin=True, dependents=deps), "IAM-001")
    assert pol([]).blast == 1.0
    assert pol(["a", "b"]).blast == 1.2
    assert pol(["a", "b", "c", "d"]).blast == 1.4
    assert pol([str(i) for i in range(20)]).blast == 1.5
    assert pol(["a", "b"]).dependents == 2 and pol(["a", "b"]).dependent_names == ["a", "b"]


def test_uncounted_blast_radius_falls_back_to_rule_default(cfg):
    f = finding(cfg, res("iam_policy", admin=True), "IAM-001")        # collector could not count
    assert f.dependents is None and f.blast == 1.3


def test_lambda_blast_counts_functions_sharing_the_role(cfg):
    f = finding(cfg, res("lambda_function", role_admin=True, secret_env_vars=[], dependents=["fn-a", "fn-b", "fn-c"]), "FN-001")
    assert f.blast == 1.3 and f.dependents == 3


# ---- the whole flow on the planted account --------------------------------------------------------------
def test_planted_context_is_measured_correctly(scanned):
    truth, result, _ = scanned
    assert check_context(result, truth) == []          # every hand-written exposure/dependents expectation holds
    assert truth.context                               # ... and there are some


def test_scan_still_read_only_with_the_new_calls(scanned):
    _, result, ss = scanned
    assert result.proof["all_read_only"] and result.proof["blocked_writes"] == 0
    assert "ec2:DescribeNetworkInterfaces" in ss.calls and "iam:ListEntitiesForPolicy" in ss.calls


def test_graph_shows_the_right_nodes(scanned):
    _, result, _ = scanned
    nodes = {n.name or n.resource_id: n for n in graph_nodes(result.findings, top=20)}
    assert nodes["prod-customer-data"].exposure_level == 1.0
    assert nodes["open-all"].exposure_level == 0.5
    assert nodes["open-rdp-v6"].exposure_level == 0.0
    assert len(nodes["AllowEverything"].dependents) == 4 and nodes["AllowEverything"].blast == 1.4
    assert draw_exposure_graph(result.findings) is not None


def test_report_explains_exposure_and_blast_radius(scanned):
    _, result, _ = scanned
    html = render_html(result)
    assert "Exposure and blast radius" in html and "dependent(s)" in html
    assert "Block Public Access is not fully on" in html and "has a public IP" in html
