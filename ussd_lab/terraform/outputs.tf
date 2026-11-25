output "instructor_instance_id" {
  value = aws_instance.host[0].id
}
output "team_instance_ids" {
  value = { for i in range(1, var.team_count + 1) : "team${i}" => aws_instance.host[i].id }
}
output "team_desktop_password" {
  value     = { for i in range(1, var.team_count + 1) : "team${i}" => random_password.team_pw[i].result }
  sensitive = true
}
output "instructor_desktop_password" {
  value     = random_password.team_pw[0].result
  sensitive = true
}
output "team_iam_access_keys" {
  value     = { for i in range(var.team_count) : "team${i + 1}" => { id = aws_iam_access_key.team[i].id, secret = aws_iam_access_key.team[i].secret } }
  sensitive = true
}
output "connect_example" {
  value = "aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=33890   then RDP to localhost:33890 as p1..p10"
}
