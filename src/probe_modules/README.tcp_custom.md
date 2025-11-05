# ZMap Probe Module: `tcp_custom`

The `tcp_custom` module is a flexible TCP probe module for ZMap. It allows for sending TCP packets with fully customizable flags, payloads, and TCP options, including support for TCP Fast Open (TFO).

This module is ideal for network research and security testing that requires sending non-standard TCP packets, such as testing firewall rules, IDS/IPS signatures, or interacting with TCP Fast Open-enabled services.

## Basic Usage

To use the module, select it with `-M tcp_custom` and provide parameters via the `--probe-args` flag:

```bash
sudo zmap -p 80 -M tcp_custom --probe-args="flags=SYN;tfo=request"
```

-----

## Probe Parameters (`--probe-args`)

Parameters are passed as a single, semicolon-separated string.

**Example:** `--probe-args="flags=SYN+PSH;payload=test;tfo=syn-data"`

### Main Parameters

  * **`flags=<FLAGS>`**

      * Sets the TCP flags for the probe packet.
      * Flags are combined with a `+` symbol.
      * If unspecified, **defaults to `SYN`**.
      * **Available flags:** `SYN`, `ACK`, `RST`, `PSH` (or `PUSH`), `FIN`, `URG`.
      * *Example:* `flags=SYN+ACK`

  * **`payload=<STRING>`**

      * Specifies a custom payload to send with the packet.
      * **Note:** Payloads are only sent with `SYN` packets if `tfo=syn-data` is also set. Payloads are sent with any other flag combination (e.g., `PSH+ACK`).
      * Supports escape sequences: `\r` (carriage return), `\n` (newline), `\t` (tab), `\xHH` (hex byte), `\\` (backslash), `\0` (null byte).
      * *Example:* `payload=GET / HTTP/1.0\r\n\r\n`
      * *Example (hex):* `payload=\xDE\xAD\xBE\xEF`

  * **`tfo=<MODE>`**

      * Configures TCP Fast Open (TFO) options.
      * **Modes:**
          * `disabled`: (Default) Do not send any TFO option.
          * `request`: Send a TFO request (empty cookie option).
          * `cookie` or `yes`: Send a TFO option with a random 8-byte cookie.
          * `syn-data` or `data`: Send a `SYN` packet with data. Requires `flags=SYN`. A random 8-byte cookie is used. If no payload is specified via `payload=...`, this mode defaults to sending a simple HTTP GET request (`GET / HTTP/1.0\r\n\r\n`).
          * `cookie:<HEX_COOKIE>`: Send a TFO option with a specific, user-supplied cookie. The cookie must be provided in hex.
          * *Example:* `tfo=cookie:deadbeef12345678`

### Secondary Parameters

  * **`options=<OPTIONS>`**

      * Configures which standard TCP options to include in the probe.
      * **Values:**
          * `no` or `false`: (Default) Send no TCP options (unless `tfo` is set).
          * `yes` or `all`: Include a standard set of options: MSS (1460), Window Scale (7), SACK Permitted, and Timestamps.
          * **Comma-separated list:** Choose specific options to include: `mss`, `wscale`, `sack`, `timestamp`, `nop`.
      * *Example:* `options=mss,wscale,nop`

  * **`window=<NUM>`**

      * Sets a specific TCP window size.
      * *Default:* `65535`

  * **`random_ack=true`**

      * Use a random 32-bit value for the TCP Acknowledgement number.
      * *Note:* Overridden by `fixed_ack`.

  * **`fixed_ack=<NUM>`**

      * Use a specific 32-bit value for the TCP Acknowledgement number.
      * *Example:* `fixed_ack=0`

  * **`mss=<NUM>`**

      * Convenience parameter to set a specific MSS value. Shorthand for `options=mss` and overrides the default MSS value.

  * **`wscale=<NUM>`**

      * Convenience parameter to set a specific Window Scale value. Shorthand for `options=wscale` and overrides the default value.

-----

## Examples

**1. Standard SYN Scan (Default Behavior)**
This is equivalent to the default `tcp_synscan` module, but uses `tcp_custom`.

```bash
sudo zmap -p 80 -M tcp_custom --probe-args="flags=SYN" -O json -f "saddr,classification"
```

**2. TFO SYN-Data Scan with Custom Payload**
Send a SYN packet with a TFO cookie and an HTTP HEAD request as the payload.

```bash
sudo zmap -p 80 -M tcp_custom --probe-args="flags=SYN;tfo=syn-data;payload=HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"
```

**3. TFO Cookie Request**
Send a SYN packet requesting a TFO cookie (empty TFO option).

```bash
sudo zmap -p 443 -M tcp_custom --probe-args="flags=SYN;tfo=request"
```

**4. PSH+ACK Scan with All TCP Options**
Send a PSH+ACK packet with a random ACK number and all common TCP options enabled.

```bash
sudo zmap -p 80 -M tcp_custom --probe-args="flags=PSH+ACK;random_ack=true;options=all"
```

**5. RST Scan with Fixed ACK Number**
Send a RST packet with an ACK number of 0.

```bash
sudo zmap -p 22 -M tcp_custom --probe-args="flags=RST;fixed_ack=0"
```

**6. FIN Scan with Specific Window Size**

```bash
sudo zmap -p 21 -M tcp_custom --probe-args="flags=FIN;window=1024"
```

-----

## Output Fields

The `tcp_custom` module provides the following fields for output (`-f "..."` or `-O json`):

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `sport` | int | TCP source port |
| `dport` | int | TCP destination port |
| `seqnum` | int | TCP sequence number (from response) |
| `acknum` | int | TCP acknowledgement number (from response) |
| `window` | int | TCP window size (from response) |
| `flag_syn` | bool | SYN flag set in response |
| `flag_ack` | bool | ACK flag set in response |
| `flag_rst` | bool | RST flag set in response |
| `flag_psh` | bool | PSH flag set in response |
| `flag_fin` | bool | FIN flag set in response |
| `flag_urg` | bool | URG flag set in response |
| `has_tfo` | bool | Response packet contains a TFO option |
| `tfo_cookie_len` | int | Length of the TFO cookie in the response |
| `classification` | string | "synack", "rst", "ack", or "other" |
| `success` | bool | 1 if SYNACK or ACK received, 0 if RST or other |
