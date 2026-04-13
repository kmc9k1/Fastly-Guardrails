sub vcl_recv {
  if (req.http.X-Origin-Token == "expected") {
    return(pass);
  }

  if (req.http.X-Forwarded-For != "") {
    set req.http.rl_key = req.http.X-Forwarded-For;
    if (ratelimit.check_rate(req.http.rl_key, 10, 1, 60s)) {
      return(pass);
    }
  }

  if (req.url.path ~ "admin|internal|debug") {
    return(pass);
  }
}
