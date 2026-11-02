package main

import rego.v1

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    rc.change.actions[_] != "delete"
    some ingress in object.get(rc.change.after, "ingress", [])
    ingress.from_port <= 22
    ingress.to_port >= 22
    "0.0.0.0/0" in object.get(ingress, "cidr_blocks", [])
    msg := sprintf("%s exposes SSH to the internet", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    rc.change.actions[_] != "delete"
    some ingress in object.get(rc.change.after, "ingress", [])
    ingress.from_port <= 3389
    ingress.to_port >= 3389
    "0.0.0.0/0" in object.get(ingress, "cidr_blocks", [])
    msg := sprintf("%s exposes RDP to the internet", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_iam_policy"
    rc.change.actions[_] != "delete"
    policy := json.unmarshal(rc.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    statement.Action == "*"
    msg := sprintf("%s grants wildcard IAM action", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_iam_policy"
    rc.change.actions[_] != "delete"
    policy := json.unmarshal(rc.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    is_array(statement.Action)
    "*" in statement.Action
    msg := sprintf("%s grants wildcard IAM action", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket_public_access_block"
    rc.change.actions[_] != "delete"
    object.get(rc.change.after, "block_public_acls", true) == false
    msg := sprintf("%s allows public S3 ACLs", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket_public_access_block"
    rc.change.actions[_] != "delete"
    object.get(rc.change.after, "block_public_policy", true) == false
    msg := sprintf("%s allows public S3 bucket policies", [rc.address])
}
