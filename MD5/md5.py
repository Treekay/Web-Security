import hashlib

if __name__ == "__main__":
    data = input('input: ')
    print('md5: ', hashlib.md5(data.encode('UTF-8')).hexdigest())