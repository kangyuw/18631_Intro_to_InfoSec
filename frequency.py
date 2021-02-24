# naive letter frequency counter for subset[0]
cipher = "csgrgzmvksynytbmpgkuiswhgrejsxthvhvftkkxgrfsgxgtvoraexklaCfztabittvpltwpqgpvwuvxjemrvmmshpibzolmpgkuigjmnikljuzmpdzimjcensrahmzswpjgsiwqouevggbicnuvrzmvcckjmzpiccybxnmvknrgszipnyrastgqqujzetvitTnbtkzwqnjzeembehrakkuiusrtiykspdlpxhcwknvfwgvhpexbxoixgecrgzzspitpstbvcckfaoblqukrzkzoponvrmblgtihitiqgoiyimipkdvaxobcqfkuiublgrZaxkzeetzbrywzgrerxcwvmsnvprjiwnkeeimedlvimgmbveefmbmvgrfhxovkqfvagxgtveuceisivsrahziqreicvuwjdoorwcpmehzztrmqgnkpvexxqgintnqgrrfgsiwpuwzgltmetlpcixnietrfwazepcvnkgqrutracziqreivrmZiruknxowruwzyphmshcvaxxipkmgbvzireewnvswvgidcsxbeptzahkipknxfxnirgvvaxnmgteuvxxixknxfslbsfapGlkaifemrpuxqgnkfaotpclkrviwqrlvgirgxjeenxaziqfxbzkzroeegvkoynakvstblgasvpobcvoknbgvheoegvutieoebqokmptveeibmqnjglkifklzgczwogegvrlwvoakvstaiervgetlaklcrzkventvexnmrctleiunxtujgetlvgplgezqspYfhvlteiijs5fki1654hfa4481rq734jjm4g14hd24"
x = []
for i in range(len(cipher)):
    if (i) % 8 == 0:
        x.append(cipher[i])
print(set(x))
dic = {}
for i in x:
    if (i in dic.keys()):
        dic[i]+=1
    else:
        dic[i] = 1
dic = {k: v for k, v in sorted(dic.items(), key=lambda item: item[1])}
print(dic)
