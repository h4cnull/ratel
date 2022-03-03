### 更新说明

版本2.0

	1.调整输出格式为csv，xlsx库的性能比较差，改为csv输出，可设置输出编码，解决乱码问题。
	2.增加poc模块支持的方法，支持多请求，支持正则，变量。
	3.支持从管道获取输入，增加常用参数。
	4.reqwest等库均把响应头的key转换为了小写，改用修改后的async-h1 client探测http，以修复这个bug。
	后续更新主要会优化代码，可能会增加被动查询接口。

### 简介

​	ratel(獾) 是一个由rust开发的信息搜集工具，专注web资产发现，支持从fofa，zoomeye API查询，提供详细的配置参数，可靠，可以从错误中恢复查询，自动去重。同时也支持主动扫描端口，探测http，提取https证书中域名。ratel 提供细粒度的http poc探测模块，支持多请求的poc，利用自定义正则表达式提取响应内容并作为后续请求的变量。ratel输出格式为csv。

### 用法和特性

<img src=.\img\usage.JPG>

​	注意：-s 被动搜集，从fofa，zoomeye api查询关键字，支持fofa，zoomeye语法，需注意命令行字符转义。-t 主动扫描。-f 需要--passive,--active,--urls,--recovery区分模式，-i从stdin读取，或者管道，同-f需要模式区分。ratel运行时会把需要注意的信息记录在xxx_notice.txt中，可以通过--recovery恢复notice中的错误记录。ratel的输出是csv格式，所有和输入域名、IP相同的资产其is_assert字段标记为TRUE，以方便筛选搜集的资产信息。

​	ratel从配置文件中读取fofa和zoomeye API key，如果不存在config文件则会自动生成。

<img src=.\img\config.JPG>

​	你可以设置多个zoomeye key，如果key没有额度了会自动使用下一个key。conn_timeout为端口扫描、http连接超时时间，http_timeout为http连接成功至读取完成的超时时间。

​	ratel提供细粒度的http poc探测模块。如下：
```text
{
  "pocs": [
    {
      "name": "multi request poc",   //必须指定
      "author": "h4cnull",
      "level": "poc level",          //u8类型：0-255，指示该poc的级别，非必须，默认1。结合config中的print_level，可以在运行时只打印重要的信息。
      "requests": [                  //请求列表，必须
        {                            //请求中的字段都是非必须
          "path_args": "/$HOST$"     //请求路径和参数，非必须，默认 /，$HOST$是特殊变量，值为当前请求的host(ip或域名)。使用该变量方便进行大量OOB测试时区分漏洞主机。
        },
        {
	  "method":"GET",            //请求方法，非必须，默认 GET，还支持POST HEAD DELETE PATCH OPTIONS TRACE方法
          "path_args": "/test.txt",
          "variables_regex": "token=\"(.*?)\" id=\"(.*?)\".*?(regex2)",  //匹配响应内容的正则表达式
          "regex_dot_all": true, // .是否匹配所有字符
          "variables_group": [["$token$",1],["$id$",2],["Variable3",3]], //用在后续请求的变量，以及变量在正则表达式中的分组。
          "rules": {    //匹配规则，非必须，不指定说明该请求默认成功。
            "status_code": 200
          }
        },
		//如果没有指定 method, path_args, headers, req_body，ratel不会重复发起请求，而是使用默认的根请求结果（请考虑follow_redirect配置的影响）做poc匹配。
        {
          "path_args": "/req3/$id$/Variable3?token=$token$", //变量可以设置在path_args,headers,req_body。
          "method": "POST",
	  "headers": {"Cookie": "token=$token$"},
          "req_body": "id=$id$",
          "rules": {
            "status_code": 501
          }
        },
	{
          "path_args": "/$id$/",  //变量可以一直使用，可用新的正则表达式匹配更新变量值
	  "rules": {
            "header":["x1","x2"], //status_code，header，body，favicon，它们之间为“与”关系。body和header是关键词列表，关键词之间也是“与”关系。
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
​	你可以使用poc模块实现指纹探测，漏洞扫描。项目提供的指纹探测文件fingers.json，主要提取自https://github.com/EdgeSecurityTeam/EHole, 以及部分作者补充的。

### 声明

​	本项目源代码开放，你可以自由使用和更改代码，但仅可用于**合法的、非商业**用途。在使用本项目编译后的工具进行检测时，你应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标使用**。你需自行承担使用本项目代码和工具的任何后果，本人将不承担任何法律及连带责任。
