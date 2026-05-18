bind_socket = "127.0.0.1:11332";
milter = yes;
upstream "local" {
    default = yes;
    self_scan = yes;
}
