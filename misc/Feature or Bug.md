#  Feature or bug?
> I just added a new feature to our utility bot but there seems to be data leak somewhere :/

after checking out the bot , trying all its cipher/helper commands , it led nowhere, then the intro cmd gave the bot's github repo , looking into to repo there wasn't much to see , but the /payload command was missing, searching more of the user's repos  we come across repo named **Eruditus-Original-Fork**, after going through it's implementation of /payload cmd  we got to know about type parameter, then using the command
`/payload query1:blitzhack flag  type:file`
we got multiple files , going through all of them , we found the actual flag in payload.gif

**Flag**: Blitz{h0w_w4s_th1s_n3w_f3atuR3?}
