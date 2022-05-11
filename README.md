# Oauth2

[RFC6479](https://datatracker.ietf.org/doc/html/rfc6749)
标准

## oauth2的几种角色

- resource owner 资源拥有者
- resource server 资源服务器
- client 第三方应用
- authorization server 认证服务器

## oauth2的几种授权方式

- 授权码模式
- 隐式（简化模式）
- 密码式
- 凭证式（客户端模式）

## spring-authorization-server

为什么使用[spring-authorization-server](https://github.com/spring-projects/spring-authorization-server)
，[Spring Security OAuth](https://spring.io/projects/spring-security-oauth)
已经过时了

### 安装使用

```xml

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>0.2.3</version>
</dependency>
```

### oauth各种模式测试

#### 授权码模式

##### 获取授权码
`http://localhost:8080/oauth2/authorize?client_id=admin&response_type=code&redirect_uri=https://pig4cloud.com`

会被重定向到login页面，上面输入的url会被保存到session
![](doc/code_login.png)

输入账号密码 admin/123456，会跳转到上面的redirect_uri,并且会带上code

`https://pig4cloud.com/?code=jmTe07jpMPWBxLwndZL07S9bX8vzp8zRU_f8Lb3WIl0Hm51pTbt4kFndxZyUnK85oIRo54OKHgtwbZkj0ExXJGbpoCyMej2SoZXbEb7BKppzJacNDYEaBpl5vPmNFWBh#/`

客户端使用post方法根据code获取用户token

`http://localhost:8080/oauth2/token`
x-www-form-urlencoded中的值
```shell
grant_type:authorization_code
code:MhL3jMZKEWYrYYETj04vdfiCv6gf0tPykoUwMtlsmVbad8dQLZMpDJAYZX8DMl5uRI2_D4UqV6vGRKgCk6RFQXwJ5ruXoPvD2ZADul8bavTKcvxZoWTlDPTNm1orPR3w
redirect_uri:https://pig4cloud.com
client_id:admin
client_secret:admin
```
返回值
```json
{
    "access_token": "eyJraWQiOiJiOGViOTY2ZC1kY2QxLTQ3MDktYTdmYi00NWQ1MTVlODhjNDAiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImFkbWluIiwibmJmIjoxNjUyMjgwMDkwLCJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MCIsImV4cCI6MTY1MjI4MDM5MCwiaWF0IjoxNjUyMjgwMDkwfQ.ZBF4wp1NeB-0aYeTjuViiiMl4QDrTvRnOkJka8E4gHHoV21Ur-pxRseLrZZrjQBEOmIverpN2xCMVHJE3C-rJ_RHftdZyl41Az9kpodANjrb7AFWWz6FNNh7v0DhxPCHFXwC48MGMpM3_4SOeryeI5w2x9mb6HB3REgVCI0-056v4MmaGB_toyjQEt2apGSkmEN9KnzbaV67SSh3AqCGDcDjl_1NfDyYRUeiOaTm9awG_2OZyCQNadOP-5fqTx5WGraRrFTQ3H-qBED1L9fenwPo3FBwmR_c5tWvJip5lv7Uffo-JwMll381BkZGySaApgNGixZDtlGS0EXdSA83nw",
    "refresh_token": "U7xU1SJAFTUJw69fHW-OuB1ze-vH03hI6W361FLuVk3vymAlK1s08gKNA-HEUTD4QSjxo1a-0BPt8SEI5G2KT76GHFWa_iDv8L7hNA2R5D-2ULbMZLM7nJXju2F6MacI",
    "token_type": "Bearer",
    "expires_in": 300
}
```