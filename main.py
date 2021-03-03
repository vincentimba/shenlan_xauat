from xauat_login import XauatLogin

if __name__ == '__main__':
    username = str(input('请输入学号：'))
    passwd = str(input('请输入密码: '))
    a = XauatLogin(username=username,
                   password=passwd)
    while 1:
        print('\n{: ^28}'.format('请输入指令'))
        print('{:-^31}'.format(''))
        print('{: ^15}'.format('1') + '-' + '{: ^15}'.format('登录'))
        print('{: ^15}'.format('2') + '-' + '{: ^15}'.format('注销'))
        print('{: ^15}'.format('3') + '-' + '{: ^15}'.format('状态'))
        print('{: ^15}'.format('4') + '-' + '{: ^15}'.format('退出'))
        print('{:-^31}\n'.format(''))
        command = str(input(''))
        if command == '1':
            a.log_in()
        elif command == '2':
            a.log_out()
        elif command == '3':
            a.get_login_info()
        elif command == '4':
            exit()
        else:
            print('\n{: ^28}'.format('格式错误'))



