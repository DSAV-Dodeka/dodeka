from base64 import urlsafe_b64decode

def add_base64_padding(unpadded: str):
    while len(unpadded) % 4 != 0:
        unpadded += "="
    return unpadded

x = "gAAAAABhyx_dtDSNz0Ffs-ysUzHgMX8S0ku6jUAwL5I8VMhX-DCSNe5LOxRSGl70Jg3jhBNbxfDGA9wKJbHa-ggpr8DZwh0ujx6plGm2Jg4rgFqN_GQ_YEF2CJOq4quDRfzGNMnCUgNbwhq7ui99y6Lpwv16RVOiZzNjULFwyk2UUHsH7E2LYZhBSeEU_mEAWDV3ZEYNLmhxTZxe8mgVPtH0VdqabSZfXOqj-uKZIzU1n6nkYgfDwQE4VQwWzTIMfXThsP_vvx4Ut3AcVbG5yWEWIeF4h_0XZNeF7uCl4I3w5TfiRWvUcJhVkcXqII5-59mUIab0FmrtUm7gXs_-aSzMvI9U54b8BcQJwVyxVbc9o6-TPtXzPdllvCql-fgW6jqLbKLo27oMaS3jiyzzIchpL8RoEooaifHmeQUT-yHuiAFU9U0n179SNYstQ5SNMcrfKX23USvVId2xWK_6tyRiVBbztMkLjGzC9zLGoMIuV_Cq8VgYnTDz5acYE03aMkSBcKdQHeovudLjYSguWjcL4uFm4GzidPToSAQF90ZJm2fGcw9PaYTDqBClMk0YlYVnrxxznhjs"
yy = add_base64_padding(x)
print(yy)
print(len(urlsafe_b64decode(yy)))
