# Fido2   

报告人：汪清扬、陈越航    
指导老师：陈杉   

## 一、背景介绍
密码是长久以来被广泛使用的加密方式，然而其本身具有很大的缺陷。据统计，大多数用户需要创建和管理十个以上的密码，因此很难兼顾密码的安全性和方便性。此外，即使提高复杂度，密码本身也依旧很容易被黑客破译。因此，为了提高信息安全，同时尽可能为用户提供便利，免密码认证是一个值得研究的方向。本项目着重认识和学习了目前较为成熟的Fido2联盟提出的免密码认证协议，使用Java在本地环境下模拟了WebAuthn和CTAP2两个子协议的认证流程，并提出了一定的理解和思考。

## 二、Fido2的免密码认证协议
Fast Identity Online （FIDO） 联盟是一个已经获得较广泛认可的、提出了一种免密认证协议组织。其协议的主要思想是，使用密码学安全硬件作为认证器（Authenticator，token、YubiKey等）以取代传统密码，并且通过绑定认证器和用户信任的客户端（浏览器等）来加强认证过程。这两个过程分别由W3C’s Web Authentication（WebAuthn）和FIDO Alliance’s Client-to-Authenticator Protocol v2.0（CTAP2）两个子协议提供规范。
WebAuthn主要实现的是用户和服务器之间，依赖于认证器的免密码认证。该协议中，每当服务器为响应登录请求而返回一个随机挑战时，不同于传统的输入密码进行验证，用户可以通过认证器（以插入YubiKey、生物验证等方式）来验证身份。这种免密码的形式有效解决了密码容易被破译的问题，同时便捷的验证方式极大提升了用户体验。
然而，采用这种验证方式，一旦用户的认证器被窃取，安全性就完全失去了保障。为了增加安全性，CTAP2协议对验证器和客户端进行了绑定。这样，验证器只对受信任的客户端进行响应，使得攻击者即使窃取了认证器，也必须通过事先与该认证器绑定过的客户端连接服务器，才能获取用户数据。免密码认证的安全性因此而拥有了双重保障。两个子协议的流程简图参见图1、图2。

![image](https://github.com/qwq-y/Fido2/assets/94696811/f5912bfc-9dae-41e0-a353-1d6e3df95143)   
图1. WebAuthn流程简图

![image](https://github.com/qwq-y/Fido2/assets/94696811/e737fbd4-51f8-4402-8fdb-e0d12e307a0d)   
图2. CTAP2流程简图

### 1. WebAuthn
具体来说，WebAuthn是规范在服务器（Server，主要是网络应用）、客户端（Clients，主要是浏览器）、认证器三者之间的协议，主要负责实现服务器挑战的免密码认证。WebAuthn协议可分为注册（Register）和认证（Authenticate）两个阶段。
在注册阶段，首先用户通过客户端向服务器发送注册请求，服务器随即生成一个包含服务器信息和用户信息的随机挑战，通过客户端返回给认证器进行验证。当客户端接收到服务器的发送的挑战时，在转发给认证器之前，会进行翻译，做必要的检查（如查验发送消息的服务器是否为用户请求注册的服务器），并附加相关认证信息。随后，挑战传输到认证器，认证器通过以硬件为基础的私钥（私钥是认证器在生产时被内嵌设定的）进行签名，同时根据服务器信息产生相应的公钥，通过客户端返回给服务器，以便后续的认证。最后，服务器收到公钥，根据一系列必要的检查决定注册是否成功。
注册成功执行后，用户再次请求登录时，即会开启认证过程。认证过程和注册过程的基本流程相似，同样需要经历用户向目标服务器发送请求，服务器向认证器发送随机挑战，认证器签名后返还给服务器，最后服务器通过比对其储存的认证信息和接收到的应答信息，决定认证结果。服务器和认证器的交流仍然通过客户端进行，且客户端需要在转发过程中做出必要的处理。

### 2. CTAP2
在WebAuthn的基础上，CTAP2通过绑定认证器和客户端来提高协议的安全性。认证器只会对受信任的（即绑定完成的）客户端发送的挑战进行响应，因此如果想要获取用户信息，攻击者必须同时接触到用户的认证器和受信任客户端（否则要重新输入认证器的PIN码进行验证和绑定），这无疑增加了攻击难度，提升了安全性。完整的CTAP2协议定义了三个阶段：注册（Setup）、绑定（Bind）、验证（Validate）。
在注册阶段，用户通过客户端向认证器设置PIN码，认证器对PIN码的规范性和数据传输的安全性进行检查后，将其储存在内部绝对安全的地方（通过硬件进行保护，不允许后续访问和修改），完成注册。此后，每当用户想要信任一个客户端时，都必须输入设置好的PIN码进行验证。在绑定阶段，用户通过客户端输入上面提及的PIN码，由认证器将其与内部储存的信息进行比对。一旦认证成功，认证器和该客户端会形成一个绑定态（代表认证器信任该客户端，之后可以对该客户端进行响应），两边分别储存绑定信息。在完成注册和绑定后，当用户想要在某服务器进行注册或登录时，服务器向验证器发送随机挑战，验证器即会启动验证过程。在验证过程中，随机挑战会先发送到客户端，客户端根据和目标验证器的绑定信息，在传送数据中添加标签后再转发给验证器。只有当验证器确认转发挑战信息的客户端是受信任的时，才会进行签名和验证。

## 三、代码实现架构
本项目的代码实现模块，以Java语言为主，创建了三个类（分别模拟Token、Client、Server三方）表示通信主体，对于协议中的每个过程分别进行模拟。模拟过程选用本地环境，在每个类中创建对应接口，用户可以自由调用并完成相应互动，完成免密码认证过程的模拟。模拟过程中采用了Fido2协议中规范的算法，使用数据库储存必要信息，并对传输数据进行了相应处理，符合实际的网络通信标准。

## 四、项目历程及成果展示
### 1. 项目历程
- 2022/09/22 - 2022/10/27：理解免密码认证和Fido2的协议，初步制定项目计划。
- 2022/10/28 - 2022/12/01：对于两个子协议分别有可运行的代码，能够模拟协议的基本过程。三个主体的代码结构如图3所示。
  ![image](https://github.com/qwq-y/Fido2/assets/94696811/00ff63ec-18a8-45c0-9460-3aacede60386)   
  图3. 12/01时初步完成的代码结构
- 2022/12/02 - 2023/01/12：进行代码的完善和细节优化，对Fido2协议的免密码认证过程可以进行较为完整的模拟。同时，我们加深了对免密码认证过程的理解和思考，尝试提出了一些自己的看法。

### 2. 成果展示
2.1. 源码地址：   
https://github.com/yhChenY/PlsAuthen2.git      

2.2. WebAuthn过程：   
考虑三个主体（Token, Client和Server）。其中，Token使用的主要的方法为rResponse()和aResponse()，分别对应注册和认证过程。Client使用的主要方法为register()和login()，用于发起注册和登陆操作。Server使用的主要方法为rChallenge()和aChallenge()，分别用于发起注册和认证时的随机挑战；以及rCheck()和aCheck()，分别用于验证Token的回应信息等是否合法。用户通过Client发起注册和登陆操作。Client会调用对应的方法，与Token和Server交换信息，实现注册和登陆操作。      

2.3. CTAP2过程：   
CTAP2主要作用在两个主体（Token和Client）之间。其中，Token可被外部调用的方法为setup()、bind()和validate()，分别对应CTAP2协议中涉及的三个状态。Client可被外部调用的方法为requestSetup()、requestBind()、verifyBind()、authorize()，分别行使响应设置、响应绑定、储存绑定态、处理信息的功能，分别和与Token的通信环节对应。可被外部调用函数的参数类型均为易于传输的String类型。     

2.4. 两个子协议的协同工作：      
运行时，CTAP2中的设置（setup()）和绑定（bind()）功能由用户单独运行。而后，用户可以调用Server的register()和login()方法模拟注册和登记，过程中Client会自动调用Token的validate()方法进行验证。对于验证成功和失败的情况，均可以返回符合预期的结果。   

2.5. 运行成果截图：      
我们在控制台打印了各个过程中生成的关键变量（见图4至图6），便于直观体会算法运行过程。
![image](https://github.com/qwq-y/Fido2/assets/94696811/d76d4039-9eab-46ed-b86c-892a06959ae2)   
图4. Token设置过程运行结果
![image](https://github.com/qwq-y/Fido2/assets/94696811/3e956f87-5311-41b6-8d42-2c1a576b72d8)   
图5. Token和Client绑定过程运行结果
![image](https://github.com/qwq-y/Fido2/assets/94696811/eeb79d0c-af72-4d07-b16c-9704cba50f61)   
图6. 注册和认证过程运行结果   
（注：pkAstr/pkBstr为双方使用ECDH算法生成的公钥；kABstr/kBAstr为双方使用ECDH算法计算出的协同密钥；encrypted为CBC算法加密后的字符串；uid为用户id经过SHA256算法生成的随机数；ids为服务器标识；sigma为签名结果的字符串形式。）

## 五、对于现有协议的思考讨论
### 1. 使用Token对Server进行验证
我们注意到，在FIDO2中，Server对Token进行了签名验证，Client和Token都没有对Server进行签名验证。（事实上Client会对Server进行验证，但是这并不在FIDO2的范围中。）考虑以下情形：Client在用户不知情的情况下被劫持，而该Client已经与用户的Token进行了绑定。当用户想要访问Server_A时，攻击者可以通过劫持的Client将会话重定向至攻击者仿造的Server_B。其导致的结果就是，用户误以为自己在于Server_A交互，而实际上在与Server_B交互。即便FIDO2引入了物理按键等要求用户确认的过程，用户也难免因为无法区分Server_A与仿造的Server_B而完成确认过程。如果在Token内引入对Server的签名验证，则可以进一步防止已Client被攻击的情况下用户登陆至钓鱼网站的情况发生。从商业角度来说，这会增加制造Token的成本，因为至少需要一块屏幕来让用户选择想要登录的Server。

### 2. 一种也许可行的攻击方式
考虑以下情景：用户拥有token_U，并且与Client绑定，攻击者拥有token_A，并且也与Client绑定。攻击者可以拦截Client与token_U之间的消息。在注册过程中，攻击者将Client发送给token_U的消息拦截，并使用token_A进行回应。同时将Client发送的消息发送给token_U，之后把token_U的回应拦截。在该情况下，一次成功的注册可以完成，但是并不是发生在用户的token_U上，而是在攻击者的token_A上。然而，在用户看来，用户是这个账号的主人。在之后的登陆过程中，攻击者只需要每次在用户登录时，使用token_A同步进行回应，用户便难以发现。而攻击者可以在其他时候登陆这个账号，窃取用户的信息。

### 3. 截断HMACSHA256的输出至前128位是否会出现碰撞
我们注意到在CTAP2的部分过程中，有对HMACSHA256的输出截断至前128位的操作。首先，很明显这会导致其安全性变得更弱。但是我们不确定这会不会真的导致出现碰撞，即两个输入对应的输出的前128位是相同的。这个哈希算法保证了对于不同的输入，其输出的256位结果是不同的，但是似乎并没有保证他们的前128位也是不同的。换句话说，如果可以保证前输出的128位是不同的，那么为什么这个算法不直接给出前128位作为结果呢？经过查询资料，我们发现在Stack Overflow网站上有一个关于类似问题的帖子（https://stackoverflow.com/questions/3026762/is-it-okay-to-truncate-a-sha256-hash-to-128-bits）。不幸的是这个帖子下并未讨论出一个明确的结果。

### 4. 用户需要对Client进行解绑的功能
在我们所参考的FIDO2版本中，Token与Client绑定后，并没有提到可以解绑。但是，由于考虑到Client可能被劫持，用户为避免Token被恶意使用，应当可以进行与Client的解绑操作。解绑步骤最好可以直接在Token中进行，以防止用户找不到可信设备的情况。而这也会对Token有要求，即引入用户交互界面。

### 5. uid长度缩减
在我们所参考的FIDO2中，Server生成的账户标识（uid）的长度为512比特。我们认为128位的uid长度已经足够，而长度较大不仅导致生成时效率降低，也会使传输的信息更长。我们测试了将uid长度缩减至128比特前后，经过循环1000000次生成所需时间，发现相比于缩减前的超过20000毫秒，缩减后的生成时间仅需不足300毫秒，效率为原来的75倍左右（这也得益于上述的对生成随机字符串时的处理）。

### 6. 生成随机数时使用的方法
在之前的版本中，我们使用Java中的Random类进行随机数的生成。经过查找资料，我们注意到Random类生成随机数时使用的是线性同余生成器（Linear Congruential Generator），而攻击者可以从获取到的输出值（甚至只需要两个输出值）中计算出该随机数生成器使用的种子值，进而预测出后续的输出值。而SecureRandom类会收集系统的一些随机事件，例如点击鼠标、进程数、内存用量等无法预测的值用于产生随机数，因此它产生的输出是具有非确定性的。我们已将使用的Random类替换为SecureRandom类。   

![image](https://github.com/qwq-y/Fido2/assets/94696811/77e1b298-a596-4694-953d-b666fafbfb0b)   
（图7. 大量随机点：左图由Random类生成，右图由SecureRandom类生成）   

### 7. 生成随机字符串时的处理
	在之前的版本中，我们生成的随机01字符串的长度等于0/1的byte位数。从实际意义上，我们需要的只是一个长度为λ的，由0和1构成的序列。因此，在表示为字符串时，并不需要相等的长度。经过修改后，我们使用bit序列进行存储，所需空间为原来的1/8，生成时的效率也获得提升。

## 六、评价反思
一方面，虽然我们对于项目的基本预期（对协议的基本流程进行模拟）已经达到，但是代码本身较为缺少实际意义。我们对于Fido2协议进行了较多的简化，并且缺少连接硬件安全工具的模块，因此在实际中很难有所应用。另一方面，虽然代码的实现结果没有令我们惊喜，但是在项目的实践过程中，我们收获了更多的理解和思考，加深了对密码学的认识，同时，对于一些工具（例如GitHub）的使用也有了更好的了解。

## 七、参考文献
[1] Barbosa M, Boldyreva A, Chen S, et al. Provable security analysis of FIDO2[C]//Annual International Cryptology Conference. Springer, Cham, 2021: 125-156.
[2] N. Bindel, C. Cremers, M. Zhao. FIDO2, CTAP 2.1, and WebAuthn 2: Provable Security and Post-Quantum Instantiation//2023 2023 IEEE Symposium on Security and Privacy (SP) (SP). San Francisco, CA, US, 2023 pp: 674-693.

## 八、成员贡献
我们共同进行协议的理解、讨论、实现和汇报，贡献比较均衡。代码实现部分，WebAuthn主要由陈越航负责，CTAP2主要由汪清扬负责。

