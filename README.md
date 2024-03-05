English [中文](README_zh.md)

### Introduction

ratel is an information gathering tool developed in Rust, focusing on web asset discovery. It supports querying from the fofa and zoomeye APIs, providing detailed configuration parameters, reliability, recovery from errors in queries, and automatic deduplication. It also supports actively scanning ports, detecting HTTP, and extracting domain names from HTTPS certificates. ratel offers a fine-grained HTTP POC detection module, supporting multi-request POCs, utilizing custom regular expressions to extract response content and use it as variables for subsequent requests. The output format of ratel is CSV.

### Usage and Features

<img src=.\img\usage.JPG>

Note: -s stands for passive collection, querying keywords from fofa and zoomeye APIs, supporting fofa and zoomeye syntax, requiring attention to command line character escaping. -t stands for active scanning. -f requires distinguishing modes with --passive, --active, --urls, --recovery. -i reads from stdin or uses a pipe, similar to -f requiring mode distinction. During ratel runtime, noteworthy information will be recorded in xxx_notice.txt, which can be recovered from errors recorded in notice using --recovery. Currently, when querying through the fofa interface, if the results contain sensitive assets, it may result in no data being returned for the entire page, only reducing the number of fofa queries per page. Ratel can reduce the number of pages queried by --recovery and --fofa-size to search for missing data.
Ratel outputs in CSV format, with the is_assert field marked as TRUE for all assets identical to the input domain name or IP, making it convenient to filter collected asset information.

Ratel reads fofa and zoomeye API keys from the configuration file, and if the config file does not exist, it will be generated automatically.

<img src=.\img\config.JPG>

You can set multiple Zoomeye keys, and if one key runs out of quota, the next key will be automatically used.`conn_timeout` refers to the timeout period for port scanning and HTTP connection establishment, while `http_timeout` refers to the timeout period from successful HTTP connection establishment to completion of reading.

Ratel provides a fine-grained HTTP POC (Proof of Concept) detection module as follows：

```text
{
  "pocs": [
    {
      "name": "multi request poc",   // needed
      "author": "h4cnull",
      "level": "5",                  // The level is "u8" type, indicates the level of this point of contact (POC), optional, default is 1. Combined with the "print_level" in the config, it allows printing only important information during runtime.
      "requests": [                  // Request link, needed. Fields in the request are all optional.
        {  
          "path_args": "/$HOST$"     // Request path and parameters, default /, $HOST$ is a special variable with a value equal to the current request's host (IP or domain name). Utilizing this variable makes it easier to differentiate vulnerable hosts during extensive out-of-band (OOB) testing.
        },
        {
          "delay":1500,              // Request with a delay of 1500 milliseconds
	  "method":"GET",            // Request method, default is GET, also supports POST, HEAD, DELETE, PATCH, OPTIONS, TRACE methods.
          "path_args": "/test.txt",
          "variables_regex": "token=\"(.*?)\" id=\"(.*?)\".*?(regex2)",  // Regular expression to match response content.
          "regex_dot_all": true, //Does the dot "." match all characters
          "variables_group": [["$token$",1],["$id$",2],["Variable3",3]], // Variables used in subsequent requests, as well as groups in regular expressions where variables are used.
          "rules": {    // Matching rules, optional. If not specified, the request is considered successful by default.
            "status_code": 200
          }
        },
		// If the method, path_args, headers, and req_body are not specified, ratel will not resend the request. Instead, it will use the default root request result for POC matching (considering the impact of the follow_redirect configuration).
        {
          "path_args": "/req3/$id$/Variable3?token=$token$", // Variables can be set in path_args, headers and req_body.
          "method": "POST",
	  "headers": {"Cookie": "token=$token$"},
          "req_body": "id=$id$",
          "rules": {
            "status_code": 501
          }
        },
	{
          "path_args": "/$id$/",  // Variables can be continuously utilized, and their values can be updated by matching with new regular expressions.
	  "rules": {
            "header":["x1","x2"], // The status_code, header, body and favicon, They have an "AND" relationship between them. "Body" and "header" are keyword lists, and keywords within them also have an "AND" relationship. If you need an "OR" relationship, you can create a separate POC.
	    "body":["x3"],
	    "favicon": -113918534
          }
        }
      ]
    },
    ...
  ]
}
```

You can use the POC module to implement fingerprint detection and vulnerability scanning. The project provides a fingerprint detection file called fingers.json, primarily extracted from "EHole", supplemented by contributions from various authors.

Statemen

The source code of this project is open and you are free to use and modify the code, but only for**legal** purposes. When using tools compiled from this project for testing, you should ensure that such actions comply with local laws and regulations, and that you have obtained sufficient authorization.**Do not use it against unauthorized targets** . You are responsible for any consequences of using this project's code and tools, and I will not bear any legal or joint liability.
