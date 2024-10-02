import hashlib
import requests
import json
import base64
import datetime
import peewee
import logging
import sys
import argparse
import time

# 设置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stdout))

# 设置时间范围为2024年
start_time = "2024-01-01"  # 开始时间
end_time = "2024-12-31"  # 结束时间

# 初始化数据库
db = peewee.SqliteDatabase('db.db')


# 定义基础模型
class BaseModel(peewee.Model):
    class Meta:
        database = db


# 定义数据模型
class IPData(BaseModel):
    uid = peewee.CharField(max_length=32, primary_key=True)
    ipport = peewee.CharField(max_length=25)
    protocol = peewee.CharField(max_length=30, null=True)
    web_title = peewee.TextField(null=True)
    domain = peewee.TextField(null=True)
    url = peewee.TextField(null=True)
    status_code = peewee.IntegerField(null=True)
    updated_at = peewee.DateField(null=True)
    company = peewee.TextField(null=True)
    icp_number = peewee.TextField(null=True)
    region = peewee.CharField(null=True)
    region_all = peewee.CharField(null=True)
    web_title_icon = peewee.BlobField(null=True)


now_time = datetime.datetime.now()


# 计算MD5
def get_md5(data: bytes) -> str:
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


# 定义Hunter API类
class HunterApi:
    def __init__(self, api_key, username='', interval=3, log_file='requested_ips.txt'):
        self.username = username
        self.api_key = api_key
        self.interval = int(interval)
        self.log_file = log_file
        self.requested_ips = self.load_requested_ips()

    def load_requested_ips(self):
        """从文件中加载已请求的IP地址"""
        try:
            with open(self.log_file, 'r') as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def log_requested_ip(self, ip):
        """记录已请求的IP地址到文件"""
        with open(self.log_file, 'a') as f:
            f.write(f"{ip}\n")

    def getdata(self, rule: str, page: int, page_size: int, is_web: bool = True, status_codes: list = None,
                start_time: str = None, end_time: str = None):
        status_codes = status_codes or [200, ]
        status_codes = [str(i) for i in status_codes]
        status_code = ','.join(status_codes)
        search_rule = base64.urlsafe_b64encode(rule.encode())

        url = f'https://hunter.qianxin.com/openApi/search'
        params = {
            'api-key': self.api_key,
            'search': search_rule.decode(),
            'page': page,
            'page_size': page_size,
            'is_web': int(is_web),
            'status_code': status_code,
            'start_time': start_time,
            'end_time': end_time,
        }

        for attempt in range(3):  # 尝试三次
            try:
                r = requests.get(url, params=params, timeout=10)
                r.raise_for_status()  # 如果返回状态码不是200，将引发HTTPError
                return r.json()
            except requests.exceptions.HTTPError as e:
                logger.error(f'[!] HTTP请求错误: {str(e)}')
                if r.status_code in [403, 429]:  # 检查是否是限速状态
                    logger.warning('[!] 超过了API请求限制，正在重试...')
                    time.sleep(5)
                continue
            except requests.exceptions.RequestException as e:
                logger.error(f'[!] 请求失败: {str(e)}')
                time.sleep(5)
                continue

        logger.error('[!] 达到请求的最大重试次数，退出')
        return {}

    def crawler(self, rule: str, page_size: int = 100, start_page: int = 1, end_page: int = None, is_web: bool = True,
                status_codes: list = None, start_time: str = None, end_time: str = None):

        page_index = start_page
        ip_count = 0

        while True:
            if end_page is not None and page_index > end_page:
                break
            logger.info(f'[*] 正在请求第 {page_index} 页数据，用规则: {rule}')
            resp_data = self.getdata(rule, page_index, page_size, is_web, status_codes, start_time, end_time)
            if resp_data.get('code') == 400 and '仅支持查询10000条数据' in resp_data.get('message', ''):
                logger.info('[v] 爬取数据完成: 到10000条上限')
                break
            elif resp_data.get('code') != 200:
                logger.info(f'[!] 在爬取第 {page_index} 页时出错: {json.dumps(resp_data, ensure_ascii=False)}')
                break

            ipdata_list = resp_data.get('data', {}).get('arr', [])
            if not ipdata_list:
                logger.info(f'[v] 爬取数据完成，没有更多数据可以爬取')
                break

            for ipdata in ipdata_list:
                try:
                    if not (ipdata.get("ip") and ipdata.get('port')):
                        continue

                    ipport = f'{str(ipdata.get("ip", "")).strip()}:{str(ipdata.get("port", "")).strip()}'

                    # 跳过已请求的IP
                    if ipport in self.requested_ips:
                        logger.info(f'[v] IP {ipport} 已请求，跳过...')
                        continue

                    web_title_icon = b''
                    try:
                        web_title_icon = base64.b64decode(ipdata.get('web_title_icon', ''))
                    except Exception as e:
                        logger.warning(f'[!] 解码web_title_icon失败: {str(e)}')

                    uid = get_md5(f'{ipport}_{ipdata.get("domain")}_{ipdata.get("url")}'.encode('utf-8'))
                    ipdata_ = IPData(
                        uid=uid,
                        ipport=ipport,
                        protocol=ipdata.get('protocol'),
                        web_title=ipdata.get('web_title'),
                        domain=ipdata.get('domain'),
                        url=ipdata.get('url'),
                        status_code=ipdata.get('status_code'),
                        updated_at=ipdata.get('updated_at'),
                        company=ipdata.get('company'),
                        icp_number=ipdata.get('number'),
                        region=ipdata.get('city'),
                        region_all=f'{ipdata.get("country")}/{ipdata.get("province")}/{ipdata.get("city")}',
                        web_title_icon=web_title_icon,
                    )
                    ipdata_.save(force_insert=True)
                    ip_count += 1
                    logger.info(
                        f'[*] 成功爬取第 {ip_count} 条数据: [{ipdata.get("url")}] [{ipdata.get("web_title")}] {ipport}')

                    # 记录请求的IP地址
                    self.log_requested_ip(ipport)

                except peewee.IntegrityError as e:
                    if 'unique' in str(e).lower():
                        logger.info(f'[v] 在第 {page_index} 页出现了重复记录')
                    else:
                        logger.error(f'[!] 保存数据到数据库出现异常: {str(e)}')
                except peewee.PeeweeException as e:
                    logger.error(f'[!] 保存数据到数据库出现异常: {str(e)}')
                except Exception as e:
                    logger.error(f'[!] 出现未知异常: {str(e)}')
            page_index += 1
            time.sleep(self.interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--start_page', default=1, type=int, help='爬取开始页数', required=False)
    parser.add_argument('--end_page', default=None, type=int, help='爬取结束页数', required=False)
    parser.add_argument('--page_size', default=100, type=int, help='每页爬取数量，最大为100', required=False)
    parser.add_argument('--ip_file', default=None, type=str, help='包含目标IP地址的文本文件路径', required=True)
    parser.add_argument('--is_web', default=1, type=int, choices=[0, 1], help="是否为网站资产", required=False)
    parser.add_argument('--interval', default=3.0, type=float, help="每次请求api之间的时间间隔", required=False)
    args = parser.parse_args()

    db.connect()
    db.create_tables([IPData, ], safe=True)

    fixed_api_key = ''

    with open(args.ip_file, 'r') as file:
        ip_list = [line.strip() for line in file if line.strip()]

    hunter = HunterApi(fixed_api_key, interval=args.interval)

    for ip in ip_list:
        rule = f'ip="{ip}"'
        logger.info(f'[*] 正在查询IP: {ip}')
        # 检查已经请求的IP，跳过已请求的IP
        if ip in hunter.requested_ips:
            logger.info(f'[v] IP {ip} 已请求，跳过...')
            continue
        hunter.crawler(rule, args.page_size, args.start_page, args.end_page, bool(args.is_web),
                       start_time=start_time, end_time=end_time)
