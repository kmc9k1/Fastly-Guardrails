acl office_acl {
  "192.0.2.0"/24;
}

sub vcl_recv {
  if (req.url.path ~ "^/healthz$" && client.ip ~ office_acl) {
    return(pass);
  }

  if (ratelimit.check_rate(client.ip, 10, 1, 60s)) {
    return(synth(429, "rate limited"));
  }
}

sub vcl_deliver {
  set resp.http.X-Trace-Edge = "checkout";
}
