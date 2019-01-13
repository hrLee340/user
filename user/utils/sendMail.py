import smtplib
from email.header import Header
from email.mime.text import MIMEText


def SendMail(receiver, mail_body):

    """

    :param receiver: 接收者具体邮箱
    :param mail_body: 发送邮件内容，支持html标签内容
    :return: 返回测试结果
    """

    # 发件人和收件人
    sender = '18855998210@163.com'
    # receiver = '1013697949@qq.com'

    # 所使用的用来发送邮件的SMTP服务器
    smtpserver = 'smtp.163.com'

    # 发送邮箱的用户名和授权码（不是登录邮箱的密码）
    username = '18855998210@163.com'
    password = 'lhrwd025689'

    # 邮件主题
    mail_title = '主题：找回密码'

    # 读取html文件内容
    # f = open('report_test.html', 'rb')  # HTML文件默认和当前文件在同一路径下，若不在同一路径下，需要指定要发送的HTML文件的路径
    # mail_body = '邮件已经发送，请查收'
    # f.close()

    # 邮件内容, 格式, 编码
    message = MIMEText(mail_body, 'html', 'utf-8')
    message['From'] = sender
    message['To'] = receiver
    message['Subject'] = Header(mail_title, 'utf-8')

    try:
        smtp = smtplib.SMTP()
        smtp.connect('smtp.163.com')
        smtp.login(username, password)
        smtp.sendmail(sender, receiver, message.as_string())
        smtp.quit()
    except smtplib.SMTPException as e:
        print(e)


# if __name__ == '__main__':
#     send_mail('1013697949@qq.com', '邮件发送，注意查收')
