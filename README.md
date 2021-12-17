### 简介

​	ratel(獾) 是一个由rust开发的信息搜集工具，支持从fofa，zoomeye API查询，提供详细的配置参数，可靠，可以从错误中恢复查询，自动去重。同时也支持主动扫描端口，探测http，提取https证书中域名。ratel 具有简单的http poc探测模块，可自定义poc，但仅支持get,post,head方法。输出为xlsx格式。

### 用法和特性

![](.\img\usage.JPG)

​	注意：-s 被动搜集，从fofa，zoomeye api查询关键字，支持fofa，zoomeye语法，需注意命令行字符转义。-t 主动扫描。-f 需要--passive,--active,--urls,--recovery区分模式。ratel运行时会把需要注意的信息记录在xxx_notice.txt中，可以通过--recovery恢复notice中的错误记录。

​	ratel的输出是xlsx格式，会自动标记输入的域名、IP资产。例如我们被动搜索如下文件，则会调用fofa查询title，fofa和zoomeye查询域名xxx.org。结果中绿色标记出包含xxx.org的资产。

```txt
title="xxx"
xxx.org
```

![](.\img\output.JPG)

​	ratel从配置文件中读取fofa和zoomeye API key，如果不存在config文件则会自动生成。

![](.\img\config.JPG)

​	你可以设置多个zoomeye key，如果key没有额度了会自动使用下一个key。与网络相关的三个重要参数conn_timeout连接超时、write_timeout发送超时、read_timeout读取超时。

​	ratel提供基本的poc探测能力，需要遵循以下格式，rules内的规则支持，status_code，header，body，favicon，它们之间为”与“关系。body和header是关键词列表，关键词之间也是”与”关系。level（u8类型：0-255）指示该poc的级别，结合config中的print_level，可以在运行时只打印重要的信息。

```json
{
	"pocs": [{
		"name":"200 OK",
		"path":"",
		"method":"get",
		"headers":{"cookie":"xxx","cmd":"id"},
		"rules":{
			"status_code":200
		}
	},
	{
		"name":"Directory list",
		"method":"get",
		"rules":{
			"body":["Directory listing for"],
			"status_code":200
		}
	},
	{
		"name":"DrayWebServer hash",
		"method":"get",
		"level": 5,
		"rules":{
			"favicon": 1013918534
		}
	}]
}
```

​	你可以使用poc模块实现指纹探测，漏洞扫描，目录扫描。项目提供的指纹探测文件fingers.json，提取自https://github.com/EdgeSecurityTeam/EHole。

### 声明

​	本项目源代码开放，你可以自由使用和更改代码，但仅可用于**合法的、非商业**用途。在使用本项目编译后的工具进行检测时，你应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标使用。**你需自行承担使用本项目代码和工具的任何后果，本人将不承担任何法律及连带责任。