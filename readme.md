### DH多方密钥交换

#### server
服务端，提供四个功能：生成公钥初始化参数；验证客户端证书合法性(未实现)；转发客户端交换密钥；转发加密消息   
_服务端不需要解密数据，所以本身不参与密钥交换_

#### master-client

财务使用，加密数据后通过服务端转发到wallet-client

#### wallet-client

钱包使用，接收master-client的消息并解密

#### other-client

其他参与者，仅参与客户端交换密钥，服务端不会将加密消息转发到此类客户端，可以启动0个或多个

#### 使用说明

1. 修改ServerApplication.clientCount,该字段代表需要参与的客户端总数。如果为2，则不需要启动 other-client，否则需要启动clientCount-2 个other-client客户端
2. 修改MasterClientApplication.data,该字段代表需要加密发送的具体消息