<p>
  ASR module that allows to work with speech transcription tools over http. <br>
  Supports two mode: POST (upload form, asr parameres stored as fields) and PUT (binary stream, asr parameters stored in header: X-ASR-OPTIONS) <br>
  Designed to work in tandem with <a href="https://github.com/akscf/asrd">asrd</a>
</p>

### Dialplan example
```
<extension name="asr-test">
  <condition field="destination_number" expression="^(3222)$">
    <action application="answer"/>
    <action application="sleep" data="1000"/>
    <action application="play_and_detect_speech" data="/tmp/test2.wav detect:curl {lang=en,some_var=some_val}"/>
    <action application="sleep" data="1000"/>
    <action application="log" data="CRIT SPEECH_RESULT=${detect_speech_result}"/>
    <action application="sleep" data="1000"/>
    <action application="hangup"/>
 </condition>
</extension>

<!--
   v1.1.2
   added special parameters: url,key,method (which replace default ones from the config)
-->
<extension name="openai-asr">
  <condition field="destination_number" expression="^(3222)$">
    <action application="answer"/>
    <action application="play_and_detect_speech" data="conference/8000/conf-welcome.wav detect:curl {url=http://new_url/, key=-alt-key-, method=put|post }"/>
    <action application="sleep" data="10000"/>
    <action application="hangup"/>
 </condition>
</extension>

```
