"""Structured schema + constraint types for standbox.

Each supported CLI is described by a SCHEMA (not code): what the "dimensions"
of a policy are (verbs/resources/namespaces for kubectl; flags for docker),
what the hard-denies are, and how the gate/container gets rendered. The
generator is generic; only these schema tables are CLI-specific. Adding a new
CLI = adding a schema dict, not copying a whole report function.
"""

import re

# ---------------------------------------------------------------- names

# The CLI tokens we can generate a sandbox for. This is the place to add
# a new one. "cli" is the user-facing name; "binary" is the command the
# gate shadows/names.
SCHEMAS = {}


def _kubectl_schema():
    return {
        "cli": "kubectl",
        "verbs": {
            # verb -> category (also the default allow-set when the use case
            # only says "read" or "write")
            "get": "read", "list": "read", "watch": "read",
            "describe": "read", "logs": "read",
            "create": "write", "apply": "write", "patch": "write",
            "update": "write", "delete": "write", "edit": "write",
            "port-forward": "write", "scale": "write", "rollout": "write",
            "exec": "privileged",
        },
        # resource -> namespaced (True) or cluster-scoped (False)
        "resources": {
            "deployments": True, "pods": True, "configmaps": True,
            "secrets": True, "services": True, "statefulsets": True,
            "daemonsets": True, "replicasets": True, "jobs": True,
            "cronjobs": True, "persistentvolumeclaims": True,
            "ingresses": True, "networkpolicies": True,
            "namespaces": False, "nodes": False, "persistentvolumes": False,
            "customresourcedefinitions": False,
        },
        # verb -> (subresource) mapping for resource-specific semantics
        "verb_target": {
            "logs": "pods/log", "port-forward": "services/portforward",
            "scale": "deployments/scale",
        },
        # always-denied tokens (even if a role granted them)
        "hard_deny": [
            "--raw", "--kubeconfig", "--as", "--as-group", "--server",
            "--user", "--cluster", "--token", "--force", "--prune",
            "--insecure-skip-tls-verify", "--context", "-A", "--all-namespaces",
        ],
        "hard_deny_verbs": ["proxy", "cp", "attach", "top"],
        # namespace flag forms
        "namespace_flags": ["-n", "--namespace"],
        "all_namespaces_flags": ["-A", "--all-namespaces"],
        # how the gate script's generic "verb RESOURCE NAME" arg parsing maps
        # to this CLI's verb-first form (kubectl is verb-first)
        "arg_model": "verb_resource_name",
        "default_binary": "kubectl",
    }


def _docker_schema():
    return {
        "cli": "docker",
        "verbs": {},
        "resources": {},
        "hard_deny": ["-v", "--volume", "--mount", "--privileged",
                      "--device", "--pid=host", "--network=host", "--net=host"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "flags_inject",
        "default_binary": "docker",
        "sandbox_flags": [
            "--read-only",
            "--tmpfs /tmp --tmpfs /run",
            "--cap-drop ALL --security-opt no-new-privileges",
            "--network none",
        ],
    }


def _git_schema():
    return {
        "cli": "git",
        # git is verb/SINGLE-word: `git status`, `git log` - no resource positional.
        "subcommands": {
            "status": "read", "log": "read", "diff": "read", "show": "read",
            "branch": "read",
            "checkout": "write", "commit": "write", "add": "write",
            "push": "write", "reset": "write",
        },
        "verbs": {},
        "resources": {},
        "hard_deny": ["--force", "-f", "--hard"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "git",
    }


def _gh_schema():
    return {
        "cli": "gh",
        # subcommand -> {action: category}
        "subcommands": {
            "pr": {"list": "read", "view": "read", "diff": "read",
                   "create": "write", "merge": "write", "close": "write", "edit": "write"},
            "issue": {"list": "read", "view": "read",
                      "create": "write", "close": "write", "edit": "write"},
            "release": {"list": "read", "view": "read",
                        "create": "write", "delete": "write"},
            "repo": {"list": "read", "view": "read", "create": "write", "delete": "write"},
            "run": {"list": "read", "view": "read"},
            "auth": {"status": "read"},
        },
        "resources": {},
        "hard_deny": ["--force", "-f"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "gh",
    }


def _aws_schema():
    return {
        "cli": "aws",
        # aws s3 ls -> sub=s3 action=ls (subcommand model, like gh)
        "subcommands": {
            "s3": {"ls": "read", "cp": "write", "rm": "write", "rb": "write",
                   "sync": "write", "mb": "write"},
            "ec2": {"describe-instances": "read", "describe-volumes": "read",
                    "run-instances": "write", "terminate-instances": "write",
                    "create-tags": "write"},
            "iam": {"list-users": "read", "list-roles": "read", "get-user": "read",
                    "create-user": "write", "delete-user": "write"},
            "lambda": {"list-functions": "read", "get-function": "read",
                       "create-function": "write", "delete-function": "write"},
        },
        "resources": {},
        "hard_deny": ["--force", "--recursive", "--delete"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "aws",
    }


def _terraform_schema():
    return {
        "cli": "terraform",
        "subcommands": {
            "plan": "read", "validate": "read", "fmt": "read",
            "output": "read", "show": "read", "state list": "read",
            "apply": "write", "destroy": "write", "import": "write",
            "init": "write", "refresh": "write",
        },
        "verbs": {},
        "resources": {},
        "hard_deny": ["-auto-approve", "-force", "-lock=false"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "terraform",
    }


def _helm_schema():
    return {
        "cli": "helm",
        "subcommands": {
            "list": "read", "get": "read", "history": "read", "repo list": "read",
            "install": "write", "upgrade": "write", "uninstall": "write",
            "template": "write",
        },
        "verbs": {},
        "resources": {},
        "hard_deny": ["--create-namespace", "--force"],
        "hard_deny_verbs": [],
        "namespace_flags": ["-n", "--namespace"],
        "all_namespaces_flags": ["-A", "--all-namespaces"],
        "arg_model": "subcommand",
        "default_binary": "helm",
    }


def _npm_schema():
    return {
        "cli": "npm",
        "subcommands": {
            "run": "read", "ls": "read", "view": "read", "show": "read",
            "audit": "read", "install": "write", "uninstall": "write",
            "publish": "write",
        },
        "verbs": {},
        "resources": {},
        "hard_deny": ["--force", "--foreground-scripts"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "npm",
    }


def _gcloud_schema():
    return {
        "cli": "gcloud",
        "subcommands": {
            "compute": {"instances": {"list": "read", "describe": "read",
                                      "start": "write", "stop": "write",
                                      "delete": "write", "ssh": "write"},
                        "disks": {"list": "read", "create": "write", "delete": "write"}},
            "iam": {"roles": {"list": "read", "describe": "read",
                              "create": "write", "delete": "write"}},
            "run": {"services": {"list": "read", "describe": "read",
                                 "deploy": "write", "delete": "write"}},
            "config": {"list": "read"},
        },
        "verbs": {},
        "resources": {},
        "hard_deny": ["--quiet", "-q"],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "arg_model": "subcommand",
        "default_binary": "gcloud",
    }


def _psql_schema():
    return {
        "cli": "psql",
        # SQL-aware: parse -c/--command (and stdin) for destructive statements.
        "arg_model": "sql",
        "verbs": {},
        "resources": {},
        "hard_deny": [],
        "hard_deny_verbs": [],
        "namespace_flags": [],
        "all_namespaces_flags": [],
        "default_binary": "psql",
        # Only read statements pass. Everything else is a deny at the gate.
        "sql_read": ["select", "with", "show", "explain", "describe",
                     "values", "table"],
        "sql_deny": ["drop", "delete", "update", "insert", "truncate", "alter",
                     "create", "grant", "revoke", "call", "do"],
        "sql_deny_verbs": ["\\copy", "copy", "\\i", "\\o"],
    }


SCHEMAS["kubectl"] = _kubectl_schema()
SCHEMAS["docker"] = _docker_schema()
SCHEMAS["git"] = _git_schema()
SCHEMAS["gh"] = _gh_schema()
SCHEMAS["aws"] = _aws_schema()
SCHEMAS["terraform"] = _terraform_schema()
SCHEMAS["helm"] = _helm_schema()
SCHEMAS["npm"] = _npm_schema()
SCHEMAS["gcloud"] = _gcloud_schema()
SCHEMAS["psql"] = _psql_schema()


def schema_for(cli):
    """Return the schema dict for a user-facing CLI name, or None."""
    key = (cli or "").strip().lower()
    if key in SCHEMAS:
        return SCHEMAS[key]
    # aliases
    if key in ("kube", "k8s"):
        return SCHEMAS["kubectl"]
    if key in ("podman", "container"):
        return SCHEMAS["docker"]
    return None


def all_clis():
    return sorted(SCHEMAS.keys())


# ------------------------------------------------------- constraint parsing

def flatten_subcommands(schema):
    """Flatten subcommands into {full_token: category} (leaves only).
    Supports three shapes:
      {"plan": {}, "apply": {}}            -> "plan": read
      {"pr": {"list": "read"}}             -> "pr list": read
      {"compute": {"instances": {"list": "read"}}} -> "compute instances list": read
    """
    out = {}

    def walk(node, prefix):
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            path = (prefix + " " + k).strip()
            if isinstance(v, dict) and v:
                walk(v, path)
            else:
                cat = v if isinstance(v, str) else "read"
                out[path] = cat

    walk(schema.get("subcommands", {}), "")
    return out


def parse_use_case(cli, text):
    """Extract constraints (verbs/resources/namespaces/flags) from a use case.
    Schema-generic: works for any CLI in SCHEMAS, not hardcoded to kubectl."""
    schema = schema_for(cli)
    if schema is None:
        return None
    t = (text or "").lower()

    resources = set()
    deny = set()

    # Token-based negation: split into words; a word immediately after
    # "no"/"not"/"without" is an explicit deny, not an allow.
    # Split on hyphens too so "read-only" -> ["read","only"].
    words = re.findall(r"[a-z0-9]+", t.replace("-", " "))

    def negated(word):
        w = word.lower()
        for i, tok in enumerate(words):
            if tok == w and i > 0 and words[i - 1] in ("no", "not", "n", "without", "never"):
                return True
        return False

    def negated_pair(sub, action):
        # "no s3 rb" / "no pr create" -> pair is negated even though neither
        # word sits directly after "no". Check window around the pair.
        for i in range(len(words) - 1):
            if words[i] == sub and words[i + 1] == action:
                if i > 0 and words[i - 1] in ("no", "not", "without", "never"):
                    return True
                # also "no create release" (action then sub reversed)
                if i > 0 and words[i - 1] in ("no", "not", "without", "never"):
                    return True
        return False

    def has_positive(word):
        # word appears AND NOT as a "no X" target, AND not inside a negated
        # phrase ("no iam roles create" -> "create" is not a positive trigger).
        for i, tok in enumerate(words):
            if tok != word:
                continue
            # directly negated: "no create"
            if i > 0 and words[i - 1] in ("no", "not", "n", "without", "never"):
                continue
            # negated phrase: find the nearest "no" before this token; if the
            # tokens between are ONLY schema nouns (no conjunction), it's part
            # of a deny phrase ("no iam roles create" - but "no jobs but
            # cronjobs" is NOT, because "but" is a conjunction).
            j = i - 1
            while j >= 0 and words[j] not in ("no", "not", "without", "never"):
                if words[j] in ("but", "and", "or", "also", "then", "however", "while"):
                    break  # conjunction ends the negated-phrase
                j -= 1
            if j >= 0 and words[j] in ("no", "not", "without", "never") and i - j <= 4:
                continue  # "no iam roles create" - words between are limited
            return True
        return False

    for res in schema.get("resources", {}):
        if has_positive(res):
            resources.add(res)
        elif negated(res):
            deny.add(res)
    # port-forward needs `services` (or `pods`) as a valid target resource
    if "port-forward" in t and "services" not in resources and "services" not in deny:
        resources.add("services")

    namespaces = re_find_namespaces(t)

    verbs = set()
    # category triggers: positive-only
    wants_write = has_positive("crud") or has_positive("write") or \
        has_positive("create") or has_positive("apply")
    wants_read = has_positive("read") or has_positive("crud") or \
        has_positive("get") or has_positive("list") or has_positive("watch")

    if schema.get("arg_model") == "sql":
        # psql: no verbs/resources; the gate enforces SQL read-only. The
        # constraint dict just mirrors the schema's read/deny keywords.
        return {
            "cli": schema["cli"],
            "resources": [],
            "namespaces": [],
            "verbs": schema.get("sql_read", ["select", "with", "show"]),
            "deny": schema.get("sql_deny", []),
            "schema": schema["cli"],
        }

    if schema.get("subcommands"):
        # subcommand model: verb = full token path (leaf), e.g. "pr list",
        # "plan", "compute instances list". Flatten first, then parse.
        flat = flatten_subcommands(schema)
        for full, cat in flat.items():
            parts = full.split()
            # check negation of ANY part, especially the leaf:
            # "no ssh" (compute instances ssh), "no plan", "no s3 rb", "no pr create"
            if negated(parts[-1]) or (len(parts) >= 2 and negated_pair(parts[0], parts[1])):
                deny.add(full)
                continue
            if negated(parts[0]) and len(parts) == 1:
                deny.add(full)
                continue
            # explicit mention: all parts appear near each other
            mentioned = __import__("re").search(
                r"\b" + r"\b.*\b".join(parts) + r"\b", t)
            if mentioned:
                verbs.add(full)
            elif cat == "read" and wants_read:
                verbs.add(full)
            elif cat == "write" and wants_write:
                verbs.add(full)
        if not verbs:
            # default read-only: all read-category leaves
            for full, cat in flat.items():
                if cat == "read":
                    verbs.add(full)
        return {
            "cli": schema["cli"],
            "resources": [],
            "namespaces": [],
            "verbs": sorted(verbs),
            "deny": sorted(deny),
            "schema": schema["cli"],
        }

    for verb, cat in schema.get("verbs", {}).items():
        if negated(verb):
            deny.add(verb)
            continue
        if has_positive(verb):
            verbs.add(verb)
        elif cat == "read" and wants_read:
            verbs.add(verb)
        elif cat == "write" and wants_write:
            verbs.add(verb)
    if not verbs and schema.get("verbs"):
        verbs = {"get", "list", "watch"}
    # docker: "no persistent mounts"
    if re.search(r"\b(?:no|without|never) (?:persistent )?mount\b|\bno.?mounts?\b", t):
        deny |= {"--mount", "--volume", "-v"}

    return {
        "cli": schema["cli"],
        "resources": sorted(resources) if resources else list(schema.get("resources", {}).keys())[:3],
        "namespaces": namespaces or (["*"] if not schema.get("namespace_flags") else ["*"]),
        "verbs": sorted(verbs),
        "deny": sorted(deny),
        "schema": schema["cli"],
    }


def re_search(pat, t):
    return re.search(r"\b" + pat + r"\b", t) is not None or pat in t


def re_find_namespaces(t):
    # Accept "namespace mfsada", "namespaces: mfsada", and "ns mfsada".
    # Skip captures that are themselves a negation word ("no namespaces").
    found = []
    for m in re.finditer(r"(?:namespaces?|ns)[ \t:]+([a-z0-9][a-z0-9-]*)", t):
        before = t[max(0, m.start() - 12):m.start()]
        if re.search(r"\bno[ -]?\s*$", before) or re.search(r"\bnot\s*$", before):
            continue
        cap = m.group(1)
        if cap in ("list", "only", "the", "a", "an", "to"):
            continue
        found.append(cap)
    return found


# ------------------------------------------------------------ policy files

POLICY_YAML = """apiVersion: standbox.io/v1
kind: SandboxPolicy
metadata:
  name: @@NAME@@
cli: @@CLI@@
bindTo:
  namespace: @@NS@@
rules:
  - verbs: [@@VERBS@@]
    resources: [@@RES@@]
    namespaces: [@@NS@@]
deny:
  - [@@DENY@@]
"""


def render_policy(name, c):
    return (POLICY_YAML
            .replace("@@NAME@@", name)
            .replace("@@CLI@@", c["cli"])
            .replace("@@VERBS@@", ", ".join(c["verbs"]))
            .replace("@@RES@@", ", ".join(c["resources"]))
            .replace("@@NS@@", ", ".join(c["namespaces"]))
            .replace("@@DENY@@", ", ".join(c.get("deny", []))))


def write_policy(path, name, c):
    with open(path, "w") as f:
        f.write(render_policy(name, c))
