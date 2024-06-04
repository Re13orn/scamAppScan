import uuid
import pathlib
import os

class Config(object):
    SECRET_KEY = str(uuid.uuid4())
    API_TOKEN = "c7a65f9847a138f076ff88cb00aa68b3bc010759b1317167002ebd4ed58a8e8b"
    UPLOAD_FOLDER = pathlib.Path(__file__).parent.joinpath('upload').resolve()
    if not os.path.isdir(UPLOAD_FOLDER):
        os.mkdir(UPLOAD_FOLDER)
    
    UPLOAD_FOLDER_JSON = os.path.join(UPLOAD_FOLDER, 'json')
    if not os.path.isdir(UPLOAD_FOLDER_JSON):
        os.mkdir(UPLOAD_FOLDER_JSON)

    UPLOAD_FOLDER_APK = os.path.join(UPLOAD_FOLDER, 'apk')
    if not os.path.isdir(UPLOAD_FOLDER_APK):
        os.mkdir(UPLOAD_FOLDER_APK)
    
    
    """
    定义恶意路径 信心指数默认为100， 范围1-100，100 信心度最高
    """
    PATH_PATTERNS = {
        "getkey?aaa=1&e=3":98,
        "inputParam?param=":97,
        "set.php?ciyu":100,
        "keywords='+this.state.mnemonicWord+'":100,
        "mnemonic+'&code=10000&source":98,
        "toString()+'&code=10000&source=android":98,
        "keywords='+t.mnemonic+'&code=10000":100,
        "aid=10&wt=1&os=1&key=": 100,
        "ciyu.php?ciyu=": 100,
        "getkey?e=": 100,
        "getmnemonic?type=": 100,
        "c=9&app=1&client=2&o=": 100,
        "ciyu=": 100,
        "ciyu.php": 100,
        "from=c&k=": 100,
        "getKey=true&pri=": 100,
        "SecureIF?VerToken=": 100,
        "qudaobao=android&mnemonic=": 100,
        "getmnemonic": 100,
        "&code=drseo828": 100,
        "'+ciyu+'&code=348608'":100
    }

    """
    定义恶意域名 信心指数默认为1
    """
    DOMAIN_PATTERNS = {
        "intoken.tw":100,
        "imtoke.net":100,
        "geqianff386.xyz":100,
        "qianff364.xyz":100,
        "geqianxz383.xyz":100,
        "qianxz364.xyz":100,
        "geqianxz385.xyz":100,
        "qianxz361.xyz":100,
        "qianff358.xyz":100,
        "geqianff381.xyz":100,
        "geqianxz378.xyz":100,
        "qianxz357.xyz":100,
        "qianff354.xyz":100,
        "geqianff358.xyz":100,
        "geqianff382.xyz":100,
        "wzsyydz.com":100,
        "jljc888.co":100,
        "hotea.lol":100,
        "tokenlinktpc.xyz":100,
        "cloudshop1.net":100,
        "usdtru.com":100,
        "imtokencn.xyz":100,
        "wxyij.xyz":100,
        "bindoke.icu":100,
        "bindoke.click":100,
        "lmtoken.sbs":100,
        "lmtoken.click":100,
        "hhttirr.com":100,
        "ktsr.cc":100,
        "tronusdt.co":100,
        "usdtstudio.cc":100,
        "ch56789.com":100,
        "skyyun.org":100,
        "qdyum.com":100,
        "cpufo.com":100,
        "im-token.skin":100,
        "tokennim.cn":100,
        "reuvip.com":100,
        "kk9.ink":100,
        "msms.life":100,
        "bindtoken.click":100,
        "dtfacai.com":100,
        "usdtcheckbot.top":100,
        "8029.com.cn":100,
        "xazydz.com":100,
        "tronous.com":100,
        "fgffgg.icu":100,
        "fliok.top":100,
        "telegact-admioo.top":100,
        "tokenpoccket.shop":100,
        "dthbkefu.vip":100,
        "n5a.net":100,
        "telegaem-gif.top":100,
        "telegaem-ych.top":100,
        "9725999.mom":100,
        "telegaem-admihj2.top":100,
        "telegaem-admihj.top":100,
        "newdatapro.com":100,
        "ellgip.cn":100,
        "amm-bot.top":100,
        "imtokencc.icu":100,
        "uufafa.com":100,
        "metamesks.io":100,
        "tokenpocketn.co":100,
        "timis.pro":100,
        "okxusd.cn":100,
        "okxtd.cn":100,
        "okxpayl.cn":100,
        "imtokenn.xyz":100,
        "manageweb.xyz":100,
        "imtokeu.net":100,
        "timiswork.top":100,
        "xxsgzs.cn":100,
        "fun-defi.xyz":100,
        "fakkmm.com":100,
        "usdteth.com":100,
        "dd1145.com":100,
        "tel-eth.com":100,
        "eth-cvc89.com":100,
        "uforce.shop":100,
        "rep-eth.com":100,
        "starwolf.cn":100,
        "ioos.top":100,
        "tonkencn.cn":100,
        "dy6188.ink":100,
        "9264lll.com":100,
        "wallethome.org":100,
        "mywode.org":100,
        "ctiaodnveif3.com":100,
        "btiaodicnsne2.com":100,
        "kkkj.me":100,
        "maskdefi.xyz":100,
        "tronscan.red":100,
        "8hg70.com":100,
        "5488a.com":100,
        "jjhgmq.com":100,
        "uforce.fun":100,
        "wiinsoft.net":100,
        "easdown.net":100,
        "appdown876.net":100,
        "appdown558.net":100,
        "rep-eth.net":100,
        "cecdd.com":100,
        "wonder123.shop":100,
        "imtoken-hk.icu":100,
        "69258.net":100,
        "cc93777.com":100,
        "tokenviewss.com":100,
        "9ovs.com":100,
        "walletyy.org":100,
        "1mwap.com":100,
        "ceshi.in":100,
        "cpapisa.top":100,
        "tron-traceon.com":100,
        "payple772.life":100,
        "webdao.vip":100,
        "payple633.info":100,
        "suiswap.me":100,
        "imtokem.bond":100,
        "accreditation.top":100,
        "thistlesisters.com":100,
        "uuuusdtt.asia":100,
        "12377.top":100,
        "payple527.info":100,
        "6kff.cn":100,
        "hgfacai.com":100,
        "223273.pw":100,
        "moviesbill.com":100,
        "123solute.xyz":100,
        "metamasks.cyou":100,
        "metamk.icu":100,
        "usdtch.com":100,
        "mathwallets.life":100,
        "westore.top":100,
        "onis9.com":100,
        "metamesk.tv":100,
        "tokenvieu.com":100,
        "maitui.top":100,
        "okt-okxpay.top":100,
        "tokeopocket.site":100,
        "ecoecokeep.com":100,
        "kinlin.im":100,
        "sssuu.com":100,
        "toiken.cc":100,
        "imtoken-token-im.com":100,
        "aligpt.buzz":100,
        "satsun.cn":100,
        "ddg.buzz":100,
        "trc1oym.com":100,
        "sbsbs.sbs":100,
        "amttc522.com":100,
        "resource-av.com":100,
        "bitproso.top":100,
        "boxin-app.com":100,
        "tnblyxggphipml8bsq2tgf3e96nkkubhhs.icu":100,
        "imtoken11.com":100,
        "shangpinshidai.com":100,
        "dy168888.vip":100,
        "123sheet.life":100,
        "cnimtoken.cyou":100,
        "od-shop.com":100,
        "jxlbusd.com":100,
        "imtokencn.club":100,
        "okx-miner.bio":100,
        "matemask.tv":100,
        "mites-app.com":100,
        "nez9002.com":100,
        "dcoinmining.com":100,
        "imqianbai.vip":100,
        "nhdaohang.xyz":100,
        "mining-leaders.pro":100,
        "gxfcgxfc.xyz":100,
        "ybihoc.cn":100,
        "lifeform.ac":100,
        "im-token.town":100,
        "metamask6.com":100,
        "etherapp.cc":100,
        "zgank.com":100,
        "trustwallet-eth.pro":100,
        "liu66.club":100,
        "imitoken.icu":100,
        "lvapp.cc":100,
        "telegramage.ltd":100,
        "imtoken.ceo":100,
        "iazada.space":100,
        "bnbm.site":100,
        "usdttrx1.com":100,
        "yuedua.cyou":100,
        "69kkh.cc":100,
        "kapmc.xyz":100,
        "juexiuluo.pro":100,
        "vipimtoken.cn":100,
        "tg-php888888.xyz":100,
        "nwdyaz2o.club":100,
        "5yiwo05x.club":100,
        "fingeryu.com":100,
        "poolxw.com":100,
        "eth-cvc79.com":100,
        "eth-cvc.com":100,
        "eth-cvc78.com":100,
        "eth-cvc68.com":100,
        "eth-cvc668.com":100,
        "cylhy.com":100,
        "otcusdt.top":100,
        "shuanglong.cc":100,
        "xms83.com":100,
        "imtoken.pt":100,
        "123loft.top":100,
        "qq1233.com":100,
        "shopifyli.com":100,
        "usdtskyou.top":100,
        "tokenvim.com":100,
        "xinbi.lol":100,
        "tokenipocket.vip":100,
        "ahegai837162.win":100,
        "9cur8sjg.club":100,
        "9jrcyb4a.club":100,
        "rt98zcaf.club":100,
        "h005j5ab.club":100,
        "defitrust.top":100,
        "tokcnpocket.pro":100,
        "facaiqwertyuiopzxc.com":100,
        "im-tokeno.com":100,
        "zhengrongshanghui.com":100,
        "veg.gold":100,
        "otcusdt.shop":100,
        "token-imm.com":100,
        "777gg.com":100,
        "hshoutai.com":100,
        "tronusdt1.com":100,
        "tronusdt8.com":100,
        "kt357.com":100,
        "wgeonline.com":100,
        "fun-defi.com":100,
        "ly88bet.com":100,
        "ll2022.com":100,
        "lm-token.online":100,
        "dingdangim.net":100,
        "doudouyi.top":100,
        "demo-rui.top":100,
        "smlab.club":100,
        "cai5888.club":100,
        "cai6888.xyz":100,
        "tronscan.tech":100,
        "bittkeep.com":100,
        "lhkj777.fun":100,
        "lhkj777.tech":100,
        "wwoyfg7e.xyz":100,
        "onis.pro":100,
        "wkudim.com":100,
        "932811.com":100,
        "931698.com":100,
        "imtokenm.pro":100,
        "tokenvims.com":100,
        "eth-cvc69.com":100,
        "lzawallet888.com":100,
        "app8.fun":100,
        "exmbztrbecls.com":100,
        "geqianxz382.xyz":100,
        "bvip.dev":100,
        "ceshi-imtoken.cn":100,
        "tpimpay.app":100,
        "a171im.com":100,
        "tokeww.com":100,
        "big76.com":100,
        "big77.com":100,
        "htim888.com":100,
        "tsw7t.com":100,
        "a191imim.com":100,
        "imtokeninc.cn":100,
        "xdhbj.com":100,
        "iimtoken.app":100,
        "shakna118.com": 100,
        "866886.icu": 100,
        "imtokenwat.com": 100,
        "a888newapi.xyz": 100,
        "foxabc.cc": 100,
        "funnel.rocks": 100,
        "upimtoken.com": 100,
        "eiwat.cn": 100,
        "bitkeeperwallet.com": 100,
        "a168im.com": 100,
        "hhbbc.org.cn": 100,
        "a112imim.com": 100,
        "newokpo.com": 100,
        "xbtcx5.com": 100,
        "a158im.xyz": 100,
        "tokenlonapis.com": 100,
        "im168168.com": 100,
        "dowm9.com": 100,
        "a182im.com": 100,
        "imdolsoel.com": 100,
        "imtoen.app": 100,
        "uniswaper.me": 100,
        "a135imiss2.com": 100,
        "setimtoken.com": 100,
        "tokenio.fun": 100,
        "hhbbk.org.cn": 100,
        "35win.cc": 100,
        "topyni.com": 100,
        "kkkkw.org.cn": 100,
        "intokenmn.com": 100,
        "im6.app": 100,
        "baby788.com": 100,
        "a181imiimm.com": 100,
        "lmtoken.cc": 100,
        "imqb2023.app": 100,
        "tokenexpert.net": 100,
        "sxsfcc.com": 100
    }

    HASH_PATTERNS = {
        "fdfa25b954480a44d2632b0aa2fd2a2f":"tokenio.fun",
        "8722294c127d7da9ac230e5ded2910a7":"tokenio.fun"
    }

    """
    日志输出等级
    """
    LOG_LEVEL = "ERROR"

    """
    目录设置
    """
    # 项目脚本的目录
    PROJECT_DIR = os.path.dirname(__file__)
    # 报告存放目录
    REPORT_DIR = os.path.join(PROJECT_DIR, "report")
    # 临时数据存放目录
    TEMP_DIRECTORY = os.path.join(PROJECT_DIR, "temp_extracted")
    # 恶意 APK 存放目录
    APK_DIRECTORY = os.path.join(PROJECT_DIR, "apkStore")

    """
    分析上下文范围设置
    """
    CONTEXT_LENGTH = 200 # 总长度200
    CONTEXT_RANGE = 100

    """
    使用ANSI转义序列来定义颜色
    主要用于在终端或命令行界面中增加文本的可读性和美观
    W (White): \033[0m - 默认的文字颜色。
    G (Green): \033[1;32m - 亮绿色。0 为普通绿色
    R (Red): \033[1;31m - 亮红色。
    O (Orange): \033[1;33m - 亮黄色，通常被解释为橙色。
    B (Blue): \033[1;34m - 亮蓝色。

    example:
    R 使 "xxoo**--==:" 这部分文本显示为亮红色。
    W 重置颜色，使之后的文本恢复默认颜色。
    G 使 "Hello world" 这部分文本显示为亮绿色。
    最后的 W 再次重置颜色，以确保之后的文本不受影响。

    print(R,"xxoo**--==:",W,G,"Hello world",W)
    print(O,"xxoo**--==:",W,B,"Hello world",W)
    """
    W = '\033[0m'
    G = '\033[0;32m'
    G1 = '\033[1;32m'
    R = '\033[0;31m'
    O = '\033[0;33m'
    B = '\033[1;34m'

    """
    APK 壳检测
    """
    SHELLFEATURE = {
        "libchaosvmp.so": "娜迦",
        "libddog.so": "娜迦",
        "libfdog.so": "娜迦",
        "libedog.so": "娜迦企业版",
        "libexec.so": "爱加密",
        "libexecmain.so": "爱加密",
        "ijiami.dat": "爱加密",
        "ijiami.ajm": "爱加密企业版",
        "libsecexe.so": "梆梆免费版",
        "libsecmain.so": "梆梆免费版",
        "libSecShell.so": "梆梆免费版",
        "libDexHelper.so": "梆梆企业版",
        "libDexHelper-x86.so": "梆梆企业版",
        "libprotectClass.so": "360 加固",
        "libjiagu.so": "360 加固",
        "libjiagu_art.so": "360 加固",
        "libjiagu_x86.so": "360 加固",
        "libegis.so": "通付盾",
        "libNSaferOnly.so": "通付盾",
        "libnqshield.so": "网秦",
        "libbaiduprotect.so": "百度",
        "aliprotect.dat": "阿里聚安全",
        "libsgmain.so": "阿里聚安全",
        "libsgsecuritybody.so": "阿里聚安全",
        "libmobisec.so": "阿里聚安全",
        "libtup.so": "腾讯",
        "libexec.so": "腾讯",
        "libshell.so": "腾讯",
        "mix.dex": "腾讯",
        "lib/armeabi/mix.dex": "腾讯",
        "lib/armeabi/mixz.dex": "腾讯",
        "libtosprotection.armeabi.so": "腾讯御安全",
        "libtosprotection.armeabi-v7a.so": "腾讯御安全",
        "libtosprotection.x86.so": "腾讯御安全",
        "libnesec.so": "网易易盾",
        "libAPKProtect.so": "APKProtect",
        "libkwscmm.so": "几维安全",
        "libkwscr.so": "几维安全",
        "libkwslinker.so": "几维安全",
        "libx3g.so": "顶像科技",
        "libapssec.so": "盛大",
        "librsprotect.so": "瑞星"
    }