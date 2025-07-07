#  The Paranomial Radio
>Our paranormal investigation team has been monitoring this abandoned radio station for weeks. The old equipment keeps broadcasting strange transmissions mixed with eerie music. We've managed to tap into their main frequency, but the signal seems to be coming from... somewhere else. 
>.........

The description mentioned a haunted radio , the blitzhack bot had a status of playing radio , while playing same music in a channel repeatedly , bot's description also had "Frequency: 1200hz"
listening to the music for a while , we hear a static audio when the music ends , which wasn't there before this challenge went live
so we use Virtual Audio Cable driver to setup a virtual audio device that we can record , set its input as discord's output
record the audio file
after opening it in audacity , spectrogram wasn't interesting so we just segment the static part and export it for further analysis
the description mentioned old-school data transmission
we then try finding tools that use specific frequency to encode information in audio, after finding OOK technique and using minimodem we get the flag

> minimodem --rx 1200 -f super_cut.wav

>Funny thing , i had done all of this already before this challenge went live , for the Feature or Bug challenge, before i had found the actual intended solution for that challenge lol

**Flag**: Blitz{th1s_w4sn't_th4t_h4rd}
