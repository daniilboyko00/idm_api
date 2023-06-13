import csv
import random
import string
from transliterate import translit


def pwgen(length):
    LETTERS = string.ascii_letters
    NUMBERS = string.digits
    paslist = ''
    for i in range(length):
        paslist += random.choice(LETTERS)+random.choice(NUMBERS)
    pas = list(paslist[0:length])
    random.shuffle(pas)
    passtring = ''.join(pas)

    return passtring


def tranlitirate(input: str):
    translit_table = {'а':'a', 'б':'b', 'в':'v', 'г':'g', 'д': 'd', 'е':'e', 'ё': 'e', 'ж': 'zh', 'з':'z', 'и': 'i', 'й': 'i', 'к': 'k',  
                      'л':'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u','ф': 'f', 'х': 'kh' ,'ц' :'ts', 
                      'ч':'ch', 'ш': 'sh' ,'щ' :'shch','ь':'', 'ы':'y', 'ъ': 'ie', 'э': 'e', 'ю': 'iu', 'я':'ia', ' ': ' ', '-':'-' 
    }
    output = ''
    for let in input.lower():
        output += translit_table[let]
    return output.title()


def prepare_a_table(file_path: str ):
    with open(file=file_path, mode='r', newline='') as fr, open('vpn_employees1.csv', mode='a', newline='') as fw:
        reader = csv.reader(fr)
        writer = csv.writer(fw)
        headers = next(reader)
        groups = {
            'юристы': 'lawyers',
            'андер': 'underwriters',
            'клиентский сервис': 'client-service',
            'ТМ':'telemarketing',
            'коллекторы':'collectors',
            'коллекторы2':'collectors'
        }
        # writer.writerow(headers)
        for line in reader:
            if line[1] == 'коллекторы2':
                full_name_en = tranlitirate(line[0]).split(' ')
                second_name_en = full_name_en[0]
                first_name_en = full_name_en[1]
                login = f'{first_name_en.lower()}.{second_name_en.lower()}'
                password = pwgen(16)
                writer.writerow(line[0:3] + [first_name_en, second_name_en, password, login,groups.get(line[1])])
            else:
                writer.writerow(line)




prepare_a_table('vpn_employees.csv')



