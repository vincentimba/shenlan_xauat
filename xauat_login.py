import requests
import re
import time
import hmac
import hashlib
import math


class ShenlanEncode(object):
    _PADCHAR = "="
    _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

    def __init__(self, challenge, info_dict, n='200', vtype='1'):
        # 定义一些实例的属性
        self.challenge = challenge
        self.info_dict = info_dict
        self.username = self.info_dict['username']
        self.ac_id = self.info_dict['acid']
        self.ip = self.info_dict['ip']
        self.n = n
        self.vtype = vtype

        # 生成用于验证的数据
        self.md5_info = self.get_md5(info_dict['password'], challenge)
        # self.md5_info = self.get_md5('', challenge)  # 实测不添加密码，只用 token 进行验证也可以登录
        self.md5 = "{MD5}" + self.md5_info
        self.info = self.get_i()
        self.chksum = self.get_sha1(self.chksum_add())

    def chksum_add(self):
        self.chksum_str_ = self.challenge + self.username
        self.chksum_str_ += self.challenge + self.md5_info
        self.chksum_str_ += self.challenge + self.ac_id
        self.chksum_str_ += self.challenge + self.ip
        self.chksum_str_ += self.challenge + self.n
        self.chksum_str_ += self.challenge + self.vtype
        self.chksum_str_ += self.challenge + self.info
        return self.chksum_str_

    def get_md5(self, password, token):
        return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

    def checksum(self, msg):
        return hashlib.sha1(msg.encode()).hexdigest()

    def xencode(self, msg, key):
        if msg == "":
            return ""
        pwd = self.sencode(msg, True)
        pwdk = self.sencode(key, False)
        if len(pwdk) < 4:
            pwdk = pwdk + [0] * (4 - len(pwdk))
        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        m = 0
        e = 0
        p = 0
        q = math.floor(6 + 52 / (n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p = p + 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]
            q = q - 1
        return self.lencode(pwd, False)

    def force(self, msg):
        ret = []
        for w in msg:
            ret.append(ord(w))
        return bytes(ret)

    def ordat(self, msg, idx):
        if len(msg) > idx:
            return ord(msg[idx])
        return 0

    def sencode(self, msg, key):
        l = len(msg)
        pwd = []
        for i in range(0, l, 4):
            pwd.append(
                self.ordat(msg, i) | self.ordat(msg, i + 1) << 8 | self.ordat(msg, i + 2) << 16
                | self.ordat(msg, i + 3) << 24)
        if key:
            pwd.append(l)
        return pwd

    def lencode(self, msg, key):
        l = len(msg)
        ll = (l - 1) << 2
        if key:
            m = msg[l - 1]
            if m < ll - 3 or m > ll:
                return
            ll = m
        for i in range(0, l):
            msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
        if key:
            return "".join(msg)[0:ll]
        return "".join(msg)

    def js_base64(self, s):
        i = 0
        b10 = 0
        x = []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8) | self._getbyte(s, i + 2)
            x.append(self._ALPHA[(b10 >> 18)])
            x.append(self._ALPHA[((b10 >> 12) & 63)])
            x.append(self._ALPHA[((b10 >> 6) & 63)])
            x.append(self._ALPHA[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = self._getbyte(s, i) << 16
            x.append(self._ALPHA[(b10 >> 18)] + self._ALPHA[((b10 >> 12) & 63)] + self._PADCHAR + self._PADCHAR)
        elif len(s) - imax == 2:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8)
            x.append(self._ALPHA[(b10 >> 18)] + self._ALPHA[((b10 >> 12) & 63)] + self._ALPHA[
                ((b10 >> 6) & 63)] + self._PADCHAR)
        else:
            pass
        return "".join(x)

    def _getbyte(self, s, i):
        x = ord(s[i])
        if (x > 255):
            print("INVALID_CHARACTER_ERR: DOM Exception 5")
            exit(0)
        return x

    def get_i(self):
        str_info_dict = re.sub("'", '"', str(self.info_dict))
        str_info_dict = re.sub(" ", '', str_info_dict)
        return "{SRBX1}" + self.js_base64(self.xencode(str_info_dict, self.challenge))

    def get_sha1(self, value):
        return hashlib.sha1(value.encode()).hexdigest()


class XauatLogin(object):
    host_login_page_url = 'http://10.186.255.33/srun_portal_pc?ac_id=1&theme=basic'  # 获取 ip
    get_challenge_url = 'http://10.186.255.33/cgi-bin/get_challenge'  # 获取 token
    log_in_url = 'http://10.186.255.33/cgi-bin/srun_portal'  # 登录 & 注销
    get_login_info_url = 'http://10.186.255.33/cgi-bin/rad_user_info'  # 获取登录后的信息
    new_headers = {
        'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Connection': 'keep-alive',
        'Cookie': 'lang=zh-CN',
        'Host': '10.186.255.33',
        'Referer': 'http://10.186.255.33/srun_portal_pc?ac_id=1&theme=basic',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36 Edg/88.0.705.81'
    }
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 '
                      'Safari/537.36 '
    }

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.login_status = False
        self.ip = self.get_ip()

    def get_ip(self):  # 获取 ip 地址
        get_ip_request = requests.get(self.host_login_page_url, headers=self.default_headers)
        ip_address = re.findall('id="user_ip" value="(.*?)">', get_ip_request.text, re.S)[0]
        if ip_address:
            print(f"获取到本机ip地址 - <{ip_address}>")
            return ip_address
        else:
            print('ip地址获取失败')
            return None

    def get_challenge(self):  # 获取 taken
        time_ = str(int(time.time() * 1000))
        get_challenge_params = {
            "callback": 'jQuery11277455887669735664_' + str(int(time.time() * 1000)),  # 这里的字符串少了一位
            "username": self.username,
            "ip": self.ip,
            '_': time_
        }
        get_challenge_request = requests.get(self.get_challenge_url,
                                             headers=self.default_headers,
                                             params=get_challenge_params)
        challenge = re.search('"challenge":"(.*?)"', get_challenge_request.text).group(1)
        if challenge:
            print('成功获取到challenge')
            return challenge
        else:
            print('获取到challenge获取失败')
            return None

    def gen_sent_keys(self, challenge, info_dict):  # 生成需要的密钥并发送至服务器
        item = ShenlanEncode(challenge=challenge, info_dict=info_dict)
        login_info_params = {
            'callback': 'jQuery1124064',  # This value can be any string, but cannot be absent
            'action': 'login',
            'username': self.username,
            'password': item.md5,
            'ac_id': item.ac_id,
            'ip': self.ip,
            'info': item.info,
            'chksum': item.chksum,
            'n': item.n,
            'type': item.vtype
        }
        log_in_response = requests.get(self.log_in_url,
                                       headers=self.new_headers,
                                       params=login_info_params)
        log_in_result = re.findall('"res":"(.*?)"', log_in_response.text, re.S)[0]
        if log_in_result == 'ok':
            self.get_login_info()
        else:
            print('{:-^41}'.format('Fail to login'))
            print('{:-^41}'.format(log_in_result))

    def log_in(self):  # 登录
        challenge = self.get_challenge()
        info_dict_ = {
            'username': f'{self.username}',
            'password': f'{self.password}',
            'ip': f'{self.ip}',  # 原代码少了一个字母 f
            'acid': '1',
            'enc_ver': 'srun_bx1'
        }
        self.gen_sent_keys(challenge=challenge, info_dict=info_dict_)

    def get_login_info(self):  # 获取表示登录状态的代码
        params = {
            'callback': 'jQuery112402812915',
            '_': str(int(time.time()))
        }
        response = requests.get(self.get_login_info_url, headers=self.default_headers, params=params)
        str_login_info = response.text
        error_info = re.search(r'"error":"(.*?)"', str_login_info).group(1)
        if error_info == 'ok':
            self.login_status = True
            user_name = re.search(r'"user_name":"(\d+)"', str_login_info).group(1)
            user_balance = re.search(r'"user_balance":(.*?),', str_login_info).group(1)
            sum_bytes = re.search(r'"sum_bytes":(\d+),', str_login_info).group(1)
            print('\n{:-^41}'.format('Login successfully'))
            print('{: ^20}'.format('User name') + '-' + '{: ^20}'.format(user_name))
            print('{: ^20}'.format('Balance') + '-' + '{: ^20}'.format(user_balance))
            print('{: ^20}'.format('Remaining MB') + '-' + '{: ^20.2f}'.format(int(sum_bytes)/1000000))
            print('{:-^41}\n'.format(''))
        else:
            print('获取登录信息失败 - ' + f'<{error_info}>')

    def log_out(self):  # 注销
        params = {
            'callback': 'jQuery11240579338170130',
            'action': 'logout',
            'ac_id': '1',
            'ip': self.ip,
            'username': self.username,
            '_': str(int(time.time()*1000))
        }
        response = requests.get(self.log_in_url, headers=self.default_headers,
                                params=params)
        log_out_result = re.findall('"res":"(.*?)"', response.text, re.S)[0]
        if log_out_result == 'ok':
            print('{:-^41}'.format('Logout successfully'))
        else:
            print('{:-^41}'.format('Fail to logout'))
            print('{:-^41}'.format(log_out_result))

