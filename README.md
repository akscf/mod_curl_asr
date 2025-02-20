<p>
  This module allows to work with speech-to-text tools over http. <br>
  Available through: asr_interface, cammnad api and events. <br>
  Designed to work in tandem with <a href="https://github.com/akscf/asrd">asrd</a>
</p>

### Few words about backend
<p>
    The backend should sopport two http methods: <br>
    <ul>
	<li><strong>POST</strong> <br>
	    this mode is equivalent a simple upload form, there is an one special filed 'file' that contains media data, other fields are the asr custom parameters. <br>
	    cURL example: curl -v http://127.0.0.1/transcribe/ -H "Content-Type: multipart/form-data" -F op1="val1" -F file="@test.wav"
	</li>
	<li><strong>PUT</strong> <br>
	    the media data caries as a binary-stream, the asr parameters can be packed in a header: X-ASR-OPTIONS (as JSON object) <br>
	    Header 'Content-Type' should contains the media type. <br>
	    cURL example: curl -v http://127.0.0.1/transcribe/ -H "Content-Type: audio/wav" -H "X-ASR-OPTIONS: {op1:val1}" --upload-file test.wav
	</li>
    </ul>
</p>

### Build and installation
 if you already have installed freeswitch and its sources: 
 - Unpack the module sources into 'src/mod/asr_tts/mod_curl_asr'
 - go to freeswitch root and edit 'configure.ac', look for variable 'AC_CONFIG_FILES' and add this module (src/mod/asr_tts/mod_curl_asr/Makefile) after 'mod_abstraction' 
 - perform: make clean (you should see how libtool rebuilding Makefiles, if it doesn't, you did something wrong) 
 - after that goto 'src/mod/asr_tts/mod_curl_asr' and perform: make clean all install 
   and copy configuration 'conf/autoload_configs/curl_asr.conf.xml' to freeswitch configs dir manually.

### Dialplan xamples
```XML
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

<extension name="openai-asr">
  <condition field="destination_number" expression="^(3222)$">
    <action application="answer"/>
    <action application="play_and_detect_speech" data="conference/8000/conf-welcome.wav detect:curl {url=http://new_url/, key=-alt-key-, method=put|post }"/>
    <action application="sleep" data="10000"/>
    <action application="hangup"/>
 </condition>
</extension>
```

### mod_quickjs
```javascript
session.ttsEngine= 'piper';
session.asrEngine= 'curl';

var txt = session.sayAndDetectSpeech('Hello, how can I halp you?', 10);
consoleLog('info', "TEXT: " + txt);
```

### Command line
```
freeswitch> curl_asr_transcribe /tmp/test.wav
+OK: How old is the Brooklyn Bridge
```

### Events
```
transcribe request: 'curl_asr::transcribe'
transcribe result : 'curl_asr::result'
```