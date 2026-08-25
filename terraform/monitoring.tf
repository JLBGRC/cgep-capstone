# Continuous monitoring for  HIPAA 164.312(b) / 164.308(a)(1)
# CloudTrail already records management events. This rule is the
# detector: KMS disable/delete on our PHI and vault CMKs -> SNS.

resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts-${local.suffix}"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Acme Health security detections"

  tags = {
    AlertOwner = "acme-health-security-ops"
    Control    = "164.312(b)"
  }
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.kms_key_lifecycle.arn]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

resource "aws_sqs_queue" "detection_dlq" {
  name                      = "${local.name_prefix}-detection-dlq-${local.suffix}"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600

  tags = {
    AlertOwner = "acme-health-security-ops"
    Purpose    = "eventbridge-detection-dlq"
  }
}

data "aws_iam_policy_document" "detection_dlq" {
  statement {
    sid    = "AllowEventBridge"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.detection_dlq.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.kms_key_lifecycle.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "detection_dlq" {
  queue_url = aws_sqs_queue.detection_dlq.id
  policy    = data.aws_iam_policy_document.detection_dlq.json
}

resource "aws_cloudwatch_event_rule" "kms_key_lifecycle" {
  name        = "${local.name_prefix}-kms-key-lifecycle"
  description = "HIPAA 164.312(b): alert if the PHI or vault CMK is disabled or scheduled for deletion."

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DisableKey", "ScheduleKeyDeletion"]
      resources = {
        ARN = [
          aws_kms_key.data.arn,
          aws_kms_key.vault.arn,
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "kms_key_lifecycle" {
  rule = aws_cloudwatch_event_rule.kms_key_lifecycle.name
  arn  = aws_sns_topic.security_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.detection_dlq.arn
  }

  depends_on = [
    aws_sns_topic_policy.security_alerts,
    aws_sqs_queue_policy.detection_dlq,
  ]
}
