# -*- coding: utf-8 -*-
# @Time    : 2020/4/8 13:27
# @Author  : 老飞机
# @File    : 猫咪.py
# @Software: pycharm

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import AES
import requests
import hashlib
import json

'''
AES/CBC/PKCS7Padding 加密解密
环境需求:
pip3 install pycryptodome
'''

class PrpCrypt(object):

    def __init__(self):
        self.key = '625222f9149e961d'.encode('utf-8')
        self.mode = AES.MODE_CBC
        self.iv = b'5efdtf6060e2o330'
        self.headers = { 'Host': '124.156.119.252:8089',
                        'Connection': 'Keep-Alive',
                        'Accept-Encoding': 'gzip',
                        'User-Agent': 'okhttp/4.2.0'
                                                }
        # block_size 128位

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16但是不是16的倍数，那就补足为16的倍数。
    def aes_Encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        text = text.encode('utf-8')

        # 这里密钥key 长度必须为16（AES-128）,24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用

        text=self.pkcs7_padding(text)
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext).decode().upper()

    def pkcs7_padding(self,data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data


    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        #  偏移量'iv'
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip("\x01").\
            rstrip("\x02").rstrip("\x03").rstrip("\x04").rstrip("\x05").\
            rstrip("\x06").rstrip("\x07").rstrip("\x08").rstrip("\x09").\
            rstrip("\x0a").rstrip("\x0b").rstrip("\x0c").rstrip("\x0d").\
            rstrip("\x0e").rstrip("\x0f").rstrip("\x10")

    def md5(self , sig):
        word = sig.encode()

        result = hashlib.md5(word)

        return result.hexdigest()

    def with_open(self):
        file = json.loads(str(open('分类.json','r',encoding='utf-8').read()))['data']
        html = '''
<style>
.chain{
text-align:center;
display: inline-block;
padding: 15px 0;
text-decoration: none;
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
background-color: #888;
border-radius: 15px;
font-size: 15px;
color: #eee;
}
.txt{
text-align:center;
margin: 0px 0% 0 0%;
<!--居中-->}
.chain{
width: 20%;
margin: 15px 2% 0 2%;
<!--控件大小-->} 
.boss div{
width:49%;
border:solid 3px gray;
float:left;}
.boss div img{
display:block;
width:100%;
height:100%;}
</style>
<body>
<div class="boss">'''

        for a in file:
            sort_id = a['id']
            page = a['page']
            file_name = a['name']
            with open(file_name+'.html' , 'w+' ,encoding= 'utf-8')as f:
                f.write('<title>{}</title>'.format(file_name) + str(html))
            self.get_data_url(sort_id,page,file_name)


    def get_data_url(self,sort_id,page,file_name):
        page1 = page
        for i in range(1,int(page)):
            try:
                page -= 1
                params = """{
  "page": %s,
  "special_id": %s
}"""%(i , sort_id)#这里不要乱改格式，不然加密对不上号
                print('\033[31m=\033[0m' *70 ,'正在爬',file_name,'总共：{} ，剩余{}页'.format(page1,page) ,'\033[31m=\033[0m' *70)
                params = self.aes_Encrypt(params)
                sig = 'QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxgparams{}version25QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxg'.format(params)
                sign = self.md5(sig)

                data = {
                        'params': params,
                        'version': 25,
                        'sign': sign
                    }

                url = 'http://150.109.116.53:8089/api/special/video'

                response = requests.post(url , headers = self.headers , data = data).text
                encrypts = json.loads(self.decrypt(str(response)))["data"]["data"]#解密
                for a in encrypts:
                    i_d = a['video_id']
                    pic = a['image']
                    title = a['video_name']
                    self.video_m3u8(i_d , pic , title , file_name)

            except Exception as d:
                print('\033[31m错误' + str(d) + '\033[0m')

    def video_m3u8(self , i_d , pic , title , file_name):
        try:
            params = '''{
  "id": %s,
  "user_id": 12093108
}'''%i_d
            params = self.aes_Encrypt(params)
            sig = 'QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxgparams{}version25QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxg'.format(params)
            sign = self.md5(sig)
            data = {
                    'params': params,
                    'version': 25,
                    'sign': sign    }
            url = 'http://150.109.116.53:8089/api/video/detail'
            response = requests.post(url , headers = self.headers , data = data).text
            encrypts = json.loads(self.decrypt(str(response)))["data"]['videos']
            for a in encrypts:
                mp4 = a['down']
                m3u8 = a['file']
                aggregate = '<h2><div><p class="txt">{}</p><img src="{}"><a class="chain" href = "{}"target="_blank">接口1</a>'.format(title, pic, mp4) + '<a class="chain" href = "{}"target="_blank">接口2</a>'.format(m3u8) + '</div></h2>'
                print(aggregate)

                with open(file_name+'.html' , 'a' , encoding= 'utf-8')as f:
                    f.write(aggregate + '\n')

        except Exception as d:
            print('\033[31m错误' + str(d) + '\033[0m')

if __name__ == '__main__':
    pc = PrpCrypt()  
    pc.with_open()
