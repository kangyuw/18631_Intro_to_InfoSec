import math
from part2_lib import *

public_key = (65537,703736009777184023089624814294592409249277452625745332757748389922801741403132753895424956388387034273861704174435411451253765105079397120958872187527398178629501434078067418714846607682059069798574406610333331388412522990466355618040442382555614571786326428324677722983316749811853794357411141610435300835386989472811731560202124433559716440618403774406013112724584220666211501545924520442351542797557629270882264182262005277582509037749501382261242519580373623050239858729306403575493062068246361660464431979222255286607177960552377520641931539650418675636738331810407143618482992844547670928974936038951567591528689023958925930857444803834201333363376485052184620872889976780466254428553439326683400737459946435445593167513822561889035880970220242237069795421833351399207596652040975400934759313225795135579755501187953271972597453681198882579090204178585215287291128291110497463202519470201521012255346320401213138901745855375111052643539718441410622424114206107789488912852766791798855906047193218554167117974489065934126633076145983625737112489908308750843216736055134034496307677388331336697043412147868755908001073328204503571374944965687211594933886539056542753201043386058223881022465258395497726598446616629809708277044876538304363851274477001948130076852019204697493260779201283467274233179625559202852390729545158599130255451772360210146408039881021326260052591922150359399352082057294370092555393061151615115792267543127892276535157873971812259349211642730474131590360278800494721445724029750557853818299117048982771060680162960060001968855117713958113729603029192550109295542279769287260929967025493700589270034205969247834931979546181490928047961637028865821415152570825885024291239135338166138255090025671890738543427997499527155351090291411875125029736688732106687581895719673633188998954000280087366975518332831060234286573912763543254548660465578591904760279949549820480025034029601503752388419439562236113784077187845247250714731196329616367136261658794480617090045807693678087647)

# public key = (pq, e)
e = public_key[0]
n = public_key[1] # pq

# 1001-digit 2xxx * 1001-digit 3xxx = 2001-digit 6xxx
# The result must be include in this range
# 1001-digit 3xxx * 1001-digit 3xxx = 2001-digit 9xxx

p = next_prime(isqrt(n))

c = 0
while (n % p != 0):
    c+=1
    p = next_prime(p)

q = n // p

print(f"prime1 is: \n {p}\n prime2 is: \n {q}")

with open("prime.txt", "w") as f:
    f.write(f"prime1 is: \n {p}\n prime2 is: \n {q}")