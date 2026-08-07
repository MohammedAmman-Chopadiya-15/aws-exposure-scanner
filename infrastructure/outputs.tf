output "api_gateway_endpoint" {
  description = "Public API Gateway Invoke URL"
  value       = "${aws_apigatewayv2_api.http_api.api_endpoint}/api/scan"
}