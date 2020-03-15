locals {
  sns_topic_arn = "${var.sns_topic_arn}"
}

resource "aws_sns_topic_subscription" "sns_notify_slack" {
  count = "${var.create}"

  topic_arn = "${local.sns_topic_arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.notify_slack.0.arn}"
}

resource "aws_lambda_permission" "sns_notify_slack" {
  count = "${var.create}"

  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.notify_slack.0.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${local.sns_topic_arn}"
}

data "null_data_source" "lambda_file" {
  inputs {
    filename = "${substr("${path.module}/functions/notify_slack.py", length(path.cwd) + 1, -1)}"
  }
}

data "null_data_source" "lambda_archive" {
  inputs {
    filename = "${substr("${path.module}/functions/notify_slack.zip", length(path.cwd) + 1, -1)}"
  }
}

data "archive_file" "notify_slack" {
  count = "${var.create}"

  type        = "zip"
  source_file = "${data.null_data_source.lambda_file.outputs.filename}"
  output_path = "${data.null_data_source.lambda_archive.outputs.filename}"
}

resource "aws_lambda_function" "notify_slack" {
  count = "${var.create}"

  filename = "${data.archive_file.notify_slack.0.output_path}"

  function_name = "${var.lambda_function_name}"

  role             = "${aws_iam_role.lambda.arn}"
  handler          = "notify_slack.lambda_handler"
  source_code_hash = "${data.archive_file.notify_slack.0.output_base64sha256}"
  runtime          = "python3.8"
  timeout          = 30
  kms_key_arn      = "${var.kms_key_arn}"

  environment {
    variables = {
      SLACK_WEBHOOK_URL = "${var.slack_webhook_url}"
      SLACK_CHANNEL     = "${var.slack_channel}"
      SLACK_USERNAME    = "${var.slack_username}"
      SLACK_EMOJI       = "${var.slack_emoji}"
      SERVICE           = "${var.service}"
    }
  }

  lifecycle {
    ignore_changes = [
      "filename",
      "last_modified",
    ]
  }
}
