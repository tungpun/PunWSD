rule GuruWS_adware_strings
{
    strings:                              
        $ = {5c 78 33 43 5c 78 37 33 5c 78 36 33 5c 78 37 32 5c 78 36 39 5c 78 37 30}
        $ = {5c 78 37 37 5c 78 37 32 5c 78 36 39 5c 78 37 34 5c 78 36 35}
        
    condition:
        any of them
}