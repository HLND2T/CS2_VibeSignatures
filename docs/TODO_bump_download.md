TODO：创建一个github action self-hosted runner上运行的定时脚本，调用 bump_download.py 用于自动更新download.yaml并基于版本号创建新的tag（如果发现新版本的话）

bump_download.py 的工作流程如下：

调用 `DepotDownloader -app 730 -depot 2347770 -os all-platform -dir cs2_depot -manifest-only` 获取2347770的文件清单

//cs2_depot/manifest_2347770_546149233531837297.txt
```
Content Manifest for Depot 2347770 

Manifest ID / date     : 546149233531837297 / 05/14/2026 21:43:16 
Total number of files  : 2901 
Total number of chunks : 57806 
Total bytes on disk    : 57532610640 
Total bytes compressed : 49127318624 


          Size Chunks File SHA                                 Flags Name
            10      1 a22a94151d8d16d32558f137f70ead7287168579     0 game\bin\built_from_cl.txt
         10753      1 4ac3b4dfb10a0829b9a20a6cbe87943d28440591     0 game\bin\win64\csgo.signatures
          8695      1 69395920ee9b771351c04070f44a5340fb86a7a5     0 game\bin\win64\vpk.signatures
         54015      1 e01f0543512e6c0fe0036284e39a074ed4ec0a6c     0 game\core\cfg\sfm_default_animation_groups.vcfg
          2270      1 ab4e0ee92367ba6d28a89dae8f6000631ffdb641     0 game\core\cfg\user_keys_default.vcfg
          2474      1 c4ff2f85048812f02c2403b0675208acfc00c7b0     0 game\core\gameinfo.gi
           135      1 7769174b103a021d6390cb2a31b758dbfff04639     0 game\core\gameinfo_branchspecific.gi
```

调用 `DepotDownloader -app 730 -depot 2347771 -os all-platform -dir cs2_depot -manifest-only`

//cs2_depot/manifest_2347771_6999933698852825529.txt 其中6999933698852825529是2347771的manifestid
```
Content Manifest for Depot 2347771 

Manifest ID / date     : 6999933698852825529 / 05/14/2026 21:43:46 
Total number of files  : 182 
Total number of chunks : 7615 
Total bytes on disk    : 7826323752 
Total bytes compressed : 5580751360 


          Size Chunks File SHA                                 Flags Name
        181608      1 0bc12517a8ee4173867d54081a6d26527ab62672     0 game\bin\win64\amd_ags_x64.dll
       9122968      9 f7da0970075cc49d1002afcccf1d47e06deb3cbf     0 game\bin\win64\animationsystem.dll
      16402584     16 261ee7a1f06cc5e01250ca55b5229af0f54db8d2     0 game\bin\win64\assetpreview.dll
        754024      1 84aaa5491087ffb7aa5453f48bdf3a837839f770     0 game\bin\win64\ati_compress_wrapper.dll
        164504      1 db6e9420cfe15b842b0ae3aee23f7080db3ff533     0 game\bin\win64\bugreporter_filequeue.dll
       1271960      2 d5f387ff10434b7a146162b8e8cb42557c27265e     0 game\bin\win64\cairo.dll
       2968216      3 257d7d3f3aa3bcb33178019fbb73f1c461664b14     0 game\bin\win64\cs2.exe
       4346120      5 612e6f443d927330b9b8ac13cc4a2a6b959cee48     0 game\bin\win64\d3dcompiler_47.dll
       1558912      2 4ef5d229709e40f3f84e46c3a28341eadbd1a044     0 game\bin\win64\dbghelp.dll
      21996904     21 bc499749a83cd7cd52673ecaa1c74760a20ba714     0 game\bin\win64\embree3.dll
       6757016      7 18108be2ab2123471d9ac264c2d1c1347915ede7     0 game\bin\win64\engine2.dll
       2262168      3 3d921c80ee8b3b6298b058aea4de303c8e0a5910     0 game\bin\win64\filesystem_stdio.dll
          2373      1 58812342d882cc4b5cb2469606929aa413e0ca16     0 game\bin\win64\foreign.signatures
       5736000      6 7d1f621599d315bbda1c7d2129b689a999a20bd8     0 game\bin\win64\gfsdk_aftermath_lib.x64.dll
        710296      1 e7f41fce69415dfbe5cb2ad47f02ba33c558a235     0 game\bin\win64\helpsystem.dll
        242840      1 a6f1e078b59478a13e2ba38ba9c5d07ce584a0cf     0 game\bin\win64\imemanager.dll
        284824      1 50051825282153646d97b100abd8621250b017ef     0 game\bin\win64\inputsystem.dll
       6627176      7 49b2ad8a4e67451776d9c4e62c7aaf62a51e9735     0 game\bin\win64\libavcodec-58.dll
       1847656      2 612200abbd317ae2c2173e52248cb5bcdcf6a9a1     0 game\bin\win64\libavformat-58.dll
        756584      1 8949c887bd27fe265d1b4df08eb2d86cc74695a5     0 game\bin\win64\libavresample-4.dll
       1572712      2 ad6e28014dedf231a8fb8a290c9b840c53812d72     0 game\bin\win64\libavutil-56.dll
       9950568     10 76a59506aa2c0665d3c1ef6b6b7e94e468803eea     0 game\bin\win64\libfbxsdk_2020_3_1.dll
        492904      1 e9484f578c843b9cc4461ed1694e4135b94c2c27     0 game\bin\win64\libfontconfig-1.dll
       1069928      2 e16c701af4b9b8fbb88129dec66a371762f7e6b6     0 game\bin\win64\libfreetype-6.dll
       1549160      2 621a4ed4981da70243398263ee59c974db8f080b     0 game\bin\win64\libglib-2.0-0.dll
        100712      1 a7d7bcfda8481ac5e5ff19dfed4da4bfc7f12917     0 game\bin\win64\libgmodule-2.0-0.dll
        334696      1 59a0af193639db6cba978482d1802346ea3cd196     0 game\bin\win64\libgobject-2.0-0.dll
         94568      1 c98a1eafa31dced7457600270c3271ba9ea60650     0 game\bin\win64\libgthread-2.0-0.dll
        352192      1 4e64337033f6a7db7d0355c6a2b54c0cbc037e3c     0 game\bin\win64\libmpg123-0.dll
        400744      1 a4a6273b4de588fa2302d45bcc994fecfb6c5fea     0 game\bin\win64\libpango-1.0-0.dll
        389992      1 a3d673d56314c10a6b742e88b4261dc9df857269     0 game\bin\win64\libpangoft2-1.0-0.dll
       1283432      2 9867b4ab6b1a430242eae51aa2b1700a1ace4a2e     0 game\bin\win64\libswscale-5.dll
        422040      1 9a8995ef4a40d4df24148ea16030d6b8e5c5ad23     0 game\bin\win64\localize.dll
       1407128      2 ba00295f84147a2df70c806f6bacf90c107d7460     0 game\bin\win64\materialsystem2.dll
       1465496      2 668fea49f0b13c1ada88baf8cb294cd8af81951a     0 game\bin\win64\meshsystem.dll
       1279128      2 37ad564ea97ace1016e9ddccefd24256847457fd     0 game\bin\win64\navsystem.dll
       2798232      3 c058328c0c5979ede9d8b5f2f24e3add5bad60fa     0 game\bin\win64\networksystem.dll
        143000      1 251a5390f6772f7f9b7c1a314a939a90fe8e151d     0 game\bin\win64\p4lib.dll
       5549720      6 5fa92f25b5679e664129267e3c1e826e0a9b719e     0 game\bin\win64\panorama.dll
       2903192      3 d8c5d80d41ebd330dd4df0b24f72bf4046b5273c     0 game\bin\win64\panoramauiclient.dll
       2985112      3 248c2776514373d52996464c408ef15cf58c5cbf     0 game\bin\win64\panorama_text_pango.dll
       5906584      6 cb6fc0dcdb54cc82f0d974d45d67d6c64d7c4829     0 game\bin\win64\particles.dll
      52162200     51 ba7938ed640a52da04df4a5db3df2c6367001f52     0 game\bin\win64\phonon.dll
        567656      1 79759ec5c92853b73627da14e5e70f6c6c580a78     0 game\bin\win64\phonon4.dll
      13474968     13 31f63fecb53f3ad50d73ca5f6e5b928f44ad91a5     0 game\bin\win64\physicsbuilder.dll
       1425560      2 86ea8db302bec165580ff42f1bc3698940a5f65e     0 game\bin\win64\propertyeditor.dll
       1804440      2 8ebd60e130d6d15df173665a9cc79ce54ca6f282     0 game\bin\win64\pulse_system.dll
        131432      1 3177661f6e066460f2c859d2d5453323b68d6eda     0 game\bin\win64\Qt5Concurrent.dll
       6288744      6 5f5173c825810bbd849e32b5e6e2cb32f6c456d2     0 game\bin\win64\Qt5Core.dll
       7007080      7 08882a63e4c0962b33376da66224655f2b1d5e06     0 game\bin\win64\Qt5Gui.dll
       5624168      6 34b499be8a25cf6b11f15946ed61bde3eee6fbd2     0 game\bin\win64\Qt5Widgets.dll
        112640      1 a21fb268583cca2da70977e842fa83c4e24f5ddc     0 game\bin\win64\qt5_plugins\imageformats\qgif.dll
        110592      1 6c36ecf5ddcf6b3228aabe8677da4ce4517afd3f     0 game\bin\win64\qt5_plugins\imageformats\qico.dll
        550400      1 aa2b5aab8e6fe5e45e01bddf080f631e9cfbc3f8     0 game\bin\win64\qt5_plugins\imageformats\qjpeg.dll
        104448      1 439258597c5d915e9fa8a46735fe5ed14e877a21     0 game\bin\win64\qt5_plugins\imageformats\qtga.dll
        523264      1 95beefb8e2599c7e648cbe9fc0ca7106c3791e5e     0 game\bin\win64\qt5_plugins\imageformats\qtiff.dll
       1616384      2 f5dc8fe31229639bd3fe28b52249af29722e0301     0 game\bin\win64\qt5_plugins\platforms\qwindows.dll
        231424      1 8fc6fa3f8cda0ffc55725d817c782115322cd574     0 game\bin\win64\qt5_plugins\styles\qwindowsvistastyle.dll
        828928      1 bbb2cff7f465f33d68bb00cb32c4ca897334cc94     0 game\bin\win64\qtadvanceddocking-qt5.dll
       4502680      5 495e86215f01d4f2295bc9d3e93fe5d8665df16f     0 game\bin\win64\rendersystemdx11.dll
       1743000      2 857ce1bd4239f7f6293b1edf9e20d46f5425f53f     0 game\bin\win64\rendersystemempty.dll
       6136984      7 703ebee0eaeda041868ea8b5e4d805307940c09b     0 game\bin\win64\rendersystemvulkan.dll
      55439512     54 5d4e4073eaed7dcba9dcb454fd8af52b33ae13d1     0 game\bin\win64\resourcecompiler.dll
        517272      1 30271cd2d44884ff51b8c17ec943a0e303779c27     0 game\bin\win64\resourcesystem.dll
       1121432      2 83720dfee49b8ab819e132fc370c422ae8d3d08c     0 game\bin\win64\scenefilecache.dll
       7013528      7 8acc81174e5d6238491ff712f90b1ce5687aee40     0 game\bin\win64\scenesystem.dll
        444568      1 5a68f78d23daf208123de5e781a0d36fe60bdebd     0 game\bin\win64\schemasystem.dll
       2785432      3 9c9c562422320c6a6e1747eb931ba94785b16aab     0 game\bin\win64\SDL3.dll
       5731992      6 612c01fe2b4481767b590ad9b3c1a406fffdaf99     0 game\bin\win64\soundsystem.dll
       2537112      3 69d88d2dc657acf08df8559ca91f133346222d68     0 game\bin\win64\steamaudio.dll
       4289176      5 16e55d461351de5472ec5fe6a041215eb278a477     0 game\bin\win64\steamnetworkingsockets.dll
        317080      1 a9fd85dbfdcee3209768facb284b8788df41c3d3     0 game\bin\win64\steam_api64.dll
        344216      1 34e5729c27357c3f31a765f33b8797068b08c1e5     0 game\bin\win64\subtools\convarhelper_subtool.dll
        222872      1 103e96d33420635400eb2ca9a72aca989d755feb     0 game\bin\win64\subtools\dashboard_subtool.dll
        356504      1 3ec92ac1264f4cb8e179ddf44264397294a82431     0 game\bin\win64\subtools\netgraph_subtool.dll
        414360      1 0dbe8ff7f69924ee5345cfab69611fa6672f1249     0 game\bin\win64\subtools\soundviewer_subtool.dll
        332440      1 e6179643757bf1b81353491077b015e84ccf12eb     0 game\bin\win64\subtools\vprof_subtool.dll
        149264      1 4b46db2a99a47ff6a6ee376f4d79f5298bff28a2     0 game\bin\win64\symsrv.dll
          1473      1 a2f63b30356a09266d8e598c4a4949ad00733230     0 game\bin\win64\system.signatures
       3966616      4 82eb09f086edd3b7a15b825d4efedcbbbbe63afc     0 game\bin\win64\tier0.dll
      13218456     13 66ebb77222cfad0c8873be6e18d361f867c3be20     0 game\bin\win64\toolframework2.dll
      50473832     49 29b8401736bcbb130ad79cde21b1cb70c4fefabf     0 game\bin\win64\v8.dll
        221336      1 9d61e3c42feae192150bf2ad18e9cafba197a15a     0 game\bin\win64\v8system.dll
       3937128      4 3a8e40f31868314b88d6514cd096dd0908f24a1b     0 game\bin\win64\v8_icui18n.dll
       2849640      3 95d6436822bcf47bb4315c0c20d69775662163b6     0 game\bin\win64\v8_icuuc.dll
       1637736      2 8402ca7e7ffb4c8db27c05c7d7c3d10c224a0750     0 game\bin\win64\v8_libbase.dll
       1455464      2 9beacc20acdc683129c258a97432e6beb8701d71     0 game\bin\win64\v8_libplatform.dll
        844136      1 97b323fba40640622eb756c42206dc088474b21a     0 game\bin\win64\v8_zlib.dll
        189080      1 831e90a532c00007144362fafcd275f05fd47791     0 game\bin\win64\valve_avi.dll
      11367576     12 12b02e4e1ecc959accd523644806f2bb1c925fff     0 game\bin\win64\valve_webm.dll
        171672      1 712556af8bac6ea1a492b70c46ada302d6660b3b     0 game\bin\win64\valve_wmf.dll
        245912      1 72ee0fa7f2ee5bceb8b026e5c9ec704989dbee51     0 game\bin\win64\vconcomm.dll
       5062808      5 0fe7efc5af3cdb067bf39a99057be8eb9d9efed2     0 game\bin\win64\vconsole2.exe
       1312408      2 186f8b328e1d5518110fac0b3b0c22e135380713     0 game\bin\win64\vfx_dx11.dll
       4610448      5 6e02ca508c3fcbd7972475e7b1530d0a2dfa12c3     0 game\bin\win64\video64.dll
       1817240      2 40d81ce02ddbb362abc3a7e164f55792b46b15f8     0 game\bin\win64\visbuilder.dll
       4476568      5 7d76a770fb6f8e335bfacefa261ee4dca75dd074     0 game\bin\win64\vphysics2.dll
       1346200      2 48c815dfc5b0b8809037d2c157bcb470f4dac52d     0 game\bin\win64\vscript.dll
       1953944      2 8743e428099dcd0d3e8773c5dbc87e7849f510e5     0 game\bin\win64\worldrenderer.dll
       3866674      5 d3ff73273e929896fa182ef64b91deaf5c82758e     0 game\core\shaders_pc_000.vpk
         25166      1 1334a5fa86748afd7326b0c2b061e8a3f3ac8605     0 game\core\shaders_pc_dir.vpk
       1728360      2 4e48ff45949c7f3cd8fd8ab5b7514ae27f44e53a     0 game\csgo\bin\legacy\csgo_legacy_app.exe
      37191832     36 59101c6cdeed70d38e1db59e880c120c888f8765     0 game\csgo\bin\win64\client.dll
       1363608      2 b6f112b3f74772ae9739921a822d960974ffb676     0 game\csgo\bin\win64\host.dll
       1897624      2 37699939ed43635bdceca16766f51cb739004268     0 game\csgo\bin\win64\matchmaking.dll
      32750232     32 89cc08a4b19bf61dbd1a3925d5cb878c9e7e2e12     0 game\csgo\bin\win64\server.dll
      78130934     79 edb1fe83da46bdb66e905c3c128d24078d25daba     0 game\csgo\shaders_pc_000.vpk
         15019      1 2a42351196fbc7b56212e77f89ba7deff23b4414     0 game\csgo\shaders_pc_dir.vpk
     105109214    108 88adb58ebbb943bc55b25df282873a064f6606ce     0 game\csgo_community_addons\cs_alpine\cs_alpine_000.vpk
     108929206    111 900d9f375ba2e320a8c945ef2364d54b7846b85a     0 game\csgo_community_addons\cs_alpine\cs_alpine_001.vpk
     106746135    108 688be350d5145aae831ac6b682b95b801eefc0d6     0 game\csgo_community_addons\cs_alpine\cs_alpine_002.vpk
     105831104    106 b89458e4263c26a05f799d7bee735cb4c85bb11d     0 game\csgo_community_addons\cs_alpine\cs_alpine_003.vpk
     107055567    112 572c49b81c03920af3aa01c0199d5c78d3881bd0     0 game\csgo_community_addons\cs_alpine\cs_alpine_004.vpk
     106911144    111 89dd1103ad0dd6ae06ffcb5d6f3b366f00ebe126     0 game\csgo_community_addons\cs_alpine\cs_alpine_005.vpk
     109845126    117 48f628aaef08460470ccb57dc48268c8b4f524b5     0 game\csgo_community_addons\cs_alpine\cs_alpine_006.vpk
     105575056    105 0172409752d1d4db697083a9812a4357a1e097b5     0 game\csgo_community_addons\cs_alpine\cs_alpine_007.vpk
     106322750    112 2cce54f91d8008f1dc013e4e99a7347d6b0f5108     0 game\csgo_community_addons\cs_alpine\cs_alpine_008.vpk
     105656344    111 7297bdf1f663a51434387ea323aa93a5bc8ee186     0 game\csgo_community_addons\cs_alpine\cs_alpine_009.vpk
     120309236    123 389285ffe9f83e79f74bf22c82d43ca4cfed65f5     0 game\csgo_community_addons\cs_alpine\cs_alpine_010.vpk
     106299152    111 4d93673c146e7cd1f79c75d1bc57bfb68269e157     0 game\csgo_community_addons\cs_alpine\cs_alpine_011.vpk
     104945248    114 63d0f36f2076ff71ab4125a613452021f10f69f7     0 game\csgo_community_addons\cs_alpine\cs_alpine_012.vpk
     107092492    111 bb2728a5eefd159ef1b14972b2ec0998ed2a7dbd     0 game\csgo_community_addons\cs_alpine\cs_alpine_013.vpk
     106382332    109 435db0f2e59edd0608257a0a618033d24a09142f     0 game\csgo_community_addons\cs_alpine\cs_alpine_014.vpk
     106435024    113 08103400d2c7ccfa3cf86806301eea6daab8f853     0 game\csgo_community_addons\cs_alpine\cs_alpine_015.vpk
     105735857    111 814c1ece29d49bb03d14b3f70446a82f2cb78145     0 game\csgo_community_addons\cs_alpine\cs_alpine_016.vpk
     107715082    112 3d63b64447b0cc154dd39ce645e7b9b330473154     0 game\csgo_community_addons\cs_alpine\cs_alpine_017.vpk
     105741486    110 0f37467b4c5a401b1f01b76ff1a877c1c6e65b4f     0 game\csgo_community_addons\cs_alpine\cs_alpine_018.vpk
      68574180     66 1277b64258e1cd00b40c4d3d612ac1661da17e1c     0 game\csgo_community_addons\cs_alpine\cs_alpine_019.vpk
        126482      1 88e58a2beb82fd92a668d3520ec826a45446a77d     0 game\csgo_community_addons\cs_alpine\cs_alpine_dir.vpk
     104986147    102 f27723fc3e7de8002d875ef29ac3f6fea321bdb5     0 game\csgo_community_addons\de_poseidon\de_poseidon_000.vpk
     107170728    104 df130376866b34df682f0d9fd39c2c956fcf3a31     0 game\csgo_community_addons\de_poseidon\de_poseidon_001.vpk
     105640796    103 a83ca2cd21d173539a646b3943f45e4505e855b9     0 game\csgo_community_addons\de_poseidon\de_poseidon_002.vpk
      90242021     88 ca054905e3fd87f103c9c95dc2455b2b51aff7e2     0 game\csgo_community_addons\de_poseidon\de_poseidon_003.vpk
         24357      1 dd526a07922c4004c5316b9d3b79677d9f8999fe     0 game\csgo_community_addons\de_poseidon\de_poseidon_dir.vpk
     107923616    112 7f4ef5cd2456e5994ead14e482cec00b97336876     0 game\csgo_community_addons\de_sanctum\de_sanctum_000.vpk
     108080581    111 e0dc4614e8ad579028fb1142dc087ad6b9d007f9     0 game\csgo_community_addons\de_sanctum\de_sanctum_001.vpk
     127183947    130 42590add17a0b615558bb2179167d3101d5150cb     0 game\csgo_community_addons\de_sanctum\de_sanctum_002.vpk
     105939600    109 a90345e76144a71833f699edcd0dffb79ab504fc     0 game\csgo_community_addons\de_sanctum\de_sanctum_003.vpk
     106111735    108 c5bbfce28523f056d91a6799f8d092cab8b8009f     0 game\csgo_community_addons\de_sanctum\de_sanctum_004.vpk
     108914134    112 155a4ac074fe5c8fbb32287481aab08b8bb97be1     0 game\csgo_community_addons\de_sanctum\de_sanctum_005.vpk
     104938940    107 bbc9e0c728b1d8001166862499f54e2f1d97e882     0 game\csgo_community_addons\de_sanctum\de_sanctum_006.vpk
     105259404    110 9feb7422ce8ce342794c43fc4a962d9bc678748b     0 game\csgo_community_addons\de_sanctum\de_sanctum_007.vpk
     109189519    117 aab3e0b1c6c0c7da3ff32c540eaa6eb97a6f9830     0 game\csgo_community_addons\de_sanctum\de_sanctum_008.vpk
     110199602    117 d8ab9e6f0c3e2d0ae11f4119f4f22aaa99e34b07     0 game\csgo_community_addons\de_sanctum\de_sanctum_009.vpk
     108059910    107 2b31ed669dbf741000ddbc8c359a14ca287e27e4     0 game\csgo_community_addons\de_sanctum\de_sanctum_010.vpk
     105896131    111 f26d17fc6d63c8d7cbcd0997b1574be8250d6f9f     0 game\csgo_community_addons\de_sanctum\de_sanctum_011.vpk
      78884376     78 c57156e52a8fbf88ad9856b87367c92cf6c68889     0 game\csgo_community_addons\de_sanctum\de_sanctum_012.vpk
        109160      1 27b0b56c9b10f62c93e9d4db964bfe47bed52069     0 game\csgo_community_addons\de_sanctum\de_sanctum_dir.vpk
     109773350    110 f15fbafb318fa500270c81f15afcda4b4281d647     0 game\csgo_community_addons\de_stronghold\de_stronghold_000.vpk
     124501876    123 6b2cb15eb2ce574e8eafd071a5bce49ca9683514     0 game\csgo_community_addons\de_stronghold\de_stronghold_001.vpk
     107885992    108 9d64227e4dee4dcf0286b46abf55fdee6b91a19b     0 game\csgo_community_addons\de_stronghold\de_stronghold_002.vpk
     104955620    103 b48813c5db0aaeb7b75415b52b0829502e9e58f0     0 game\csgo_community_addons\de_stronghold\de_stronghold_003.vpk
     107232168    104 97ca11de79cb9bdebc0e0e34136d2c6bde05eafc     0 game\csgo_community_addons\de_stronghold\de_stronghold_004.vpk
     106319860    108 135968c4d60e8218a9ebd4313ea22f454d6c428a     0 game\csgo_community_addons\de_stronghold\de_stronghold_005.vpk
     106328092    106 e4b423c04772961a4b002da0e43c7968d7008e9e     0 game\csgo_community_addons\de_stronghold\de_stronghold_006.vpk
     105976232    106 1c538cc0b100ce3874459842ca56b6f9f9caa7d5     0 game\csgo_community_addons\de_stronghold\de_stronghold_007.vpk
     105374374    103 b877fc7396a13a51ba5738e308e3ace05b822119     0 game\csgo_community_addons\de_stronghold\de_stronghold_008.vpk
     105006606    102 103b857e5e049806d537a491ee5d61a242bee563     0 game\csgo_community_addons\de_stronghold\de_stronghold_009.vpk
     120975005    118 24e70a017e75de0ef08425a2d09ab0091416a203     0 game\csgo_community_addons\de_stronghold\de_stronghold_010.vpk
     104870986    102 33c1afea3dce0b9e51beca1410bc89540ec9048a     0 game\csgo_community_addons\de_stronghold\de_stronghold_011.vpk
     116964132    116 7f82cc3eb4028a52a2e765627b28f5d413945bc1     0 game\csgo_community_addons\de_stronghold\de_stronghold_012.vpk
     107400297    105 fb460ab77d0ed17faa515506a8c3719673b8f60c     0 game\csgo_community_addons\de_stronghold\de_stronghold_013.vpk
     104071041    103 19defdf2bb42703f39c21ced2ecf0f847f4959c3     0 game\csgo_community_addons\de_stronghold\de_stronghold_014.vpk
        121060      1 12128786e524fec64407a51d2b63285a6298b504     0 game\csgo_community_addons\de_stronghold\de_stronghold_dir.vpk
     108021069    106 2f20647b4c6591b2e08591ea8ba421f8c2a8afee     0 game\csgo_community_addons\de_warden\de_warden_000.vpk
     110304770    109 98c682684f9e7a58c20a2ab3121ee855170264f6     0 game\csgo_community_addons\de_warden\de_warden_001.vpk
     106372627    105 4a7b57edffffaaba5791b7663500219fe7398aef     0 game\csgo_community_addons\de_warden\de_warden_002.vpk
     106511500    104 12c16a0e6dffa7df0958fef71b58528ac69843aa     0 game\csgo_community_addons\de_warden\de_warden_003.vpk
     108053470    108 db1e2fade242e1351c3044338edb0ae8665e28bd     0 game\csgo_community_addons\de_warden\de_warden_004.vpk
     104964150    102 84468463e9094b1a65be5b320a04e15033a99bb1     0 game\csgo_community_addons\de_warden\de_warden_005.vpk
     109960457    107 59b1c407a625633bbf5c257e6fee8cbc7a090074     0 game\csgo_community_addons\de_warden\de_warden_006.vpk
     105661423    107 a15915ec1237ab1a9ad81a28f5ef1296b7a37812     0 game\csgo_community_addons\de_warden\de_warden_007.vpk
     106334767    104 5821c2c87e541c72c957c779ef4c20952dfdfb3b     0 game\csgo_community_addons\de_warden\de_warden_008.vpk
     106293529    105 e5e90a354537b498393b93dbca5ba668ece2ddad     0 game\csgo_community_addons\de_warden\de_warden_009.vpk
     105462767    102 e05f0287e83790f7ff483d00a0fd9ea2f7c8d314     0 game\csgo_community_addons\de_warden\de_warden_010.vpk
     109331645    105 81f9c389717d29fd9ba5e1e8117395a5a4fb368c     0 game\csgo_community_addons\de_warden\de_warden_011.vpk
     108943601    107 11fca34f7e473c18ea7c548bc5c95c51b1f87ef1     0 game\csgo_community_addons\de_warden\de_warden_012.vpk
      45637976     45 f3ab81339d489c9ad77ce7a6a694e00af3a57cab     0 game\csgo_community_addons\de_warden\de_warden_013.vpk
         97137      1 d83e192edd2863ada18dd9926a7a97e683bbb459     0 game\csgo_community_addons\de_warden\de_warden_dir.vpk
     188163933    180 c04da01bc0ddb597014c339dc259baa10db4739e     0 game\csgo_core\shaders_pc_000.vpk
      74805442     77 84f0c0f2799f8745c5b295db7d6cdf853259f603     0 game\csgo_core\shaders_pc_001.vpk
         15030      1 4ef2dcba1442461c12c38badfc2d40c62545fb41     0 game\csgo_core\shaders_pc_dir.vpk
```

调用 `DepotDownloader -app 730 -depot 2347773 -os all-platform -dir cs2_depot -manifest-only`

//manifest_2347773_1005161166845732962.txt  其中 1005161166845732962 是 2347773 的 manifestid

```
Content Manifest for Depot 2347773 

Manifest ID / date     : 1005161166845732962 / 05/14/2026 21:44:01 
Total number of files  : 133 
Total number of chunks : 7102 
Total bytes on disk    : 7331490406 
Total bytes compressed : 5190914752 


          Size Chunks File SHA                                 Flags Name
        154364      1 03eafc0d5279b6764e29b9df993f0f5eb95b9b96     0 game\bin\linuxsteamrt64\cs2
         84104      1 17f3c133b5c62e6e2bbb0280e038912414412579     0 game\bin\linuxsteamrt64\fltlnx64.flt
      12840672     13 d4363098d539b5d7448b4c02481bd9f41375bda4     0 game\bin\linuxsteamrt64\libanimationsystem.so
       3678216      4 68f95c77a3ab19b380f142ab7e6ccb543af9d37c     0 game\bin\linuxsteamrt64\libavcodec.so.58
        888848      1 bcfdd74b8bc4268cc6af190a10c8d64d27b71bc9     0 game\bin\linuxsteamrt64\libavformat.so.58
        129496      1 4895da33d08a56dfb48daa79a3bcee9f9c361649     0 game\bin\linuxsteamrt64\libavresample.so.4
        712672      1 451e7c11727fefe58f2cca8fc0e0cd0bc562f43e     0 game\bin\linuxsteamrt64\libavutil.so.56
       1737748      2 1465c9edd18fcaf760cc73fdc2dd8c904015ddfc     0 game\bin\linuxsteamrt64\libcairo.so
       9917832     10 4b714f8ca6f69f29ea3e7745b873ac84a23d596f     0 game\bin\linuxsteamrt64\libengine2.so
       3098056      3 5cb86c6714075c5ce27f2bcd29f0dc4965f81a8b     0 game\bin\linuxsteamrt64\libfilesystem_stdio.so
       1304272      2 0af1352041c54e16129773dc8d038872f9f839be     0 game\bin\linuxsteamrt64\libfontconfig.so.1
       3930056      4 0b64e7c4eab1a6313867cb39c0fafbeb026aac7f     0 game\bin\linuxsteamrt64\libfreetype.so.6
        492372      1 c2923ae1b649de9995c27e8640e34568b9e8cf90     0 game\bin\linuxsteamrt64\libinputsystem.so
        661072      1 49259d501b5e8d5b7030c3631fd96eb88f1cfbf7     0 game\bin\linuxsteamrt64\liblocalize.so
       1701424      2 0edc979400f3f5a96b40e85c98a9a2a87f2de3d1     0 game\bin\linuxsteamrt64\libmaterialsystem2.so
       1751212      2 7ff18c9327c02e24ea1c64fe2c9639235b0c6ad7     0 game\bin\linuxsteamrt64\libmeshsystem.so
       1051154      2 312f15ffc6ca79979618858b7e371c056b5b74b2     0 game\bin\linuxsteamrt64\libmpg123.so.0
       4644204      5 edc62cee2f06c8caf10a98b0e358943a9d78337f     0 game\bin\linuxsteamrt64\libnetworksystem.so
         35112      1 5f38ba115a525c4dee3dea7d9625a2164b84d457     0 game\bin\linuxsteamrt64\libogg.so.0
       1278424      2 e99953922de86b898b2f0c9abc38ae24c6aea2b4     0 game\bin\linuxsteamrt64\libpango-1.0.so.0
        442632      1 9e20da60c2343c610624175113428f4089236585     0 game\bin\linuxsteamrt64\libpangoft2-1.0.so.0
       6600864      7 7124bc23e140e73285da385da70e911a99aa98fd     0 game\bin\linuxsteamrt64\libpanorama.so
       4860352      5 82da33241f8a567e1e0c5048b6024fc4a03bda3c     0 game\bin\linuxsteamrt64\libpanoramauiclient.so
       3072772      3 213431bea79d1543020cb7e9ded3f3e11206f5e2     0 game\bin\linuxsteamrt64\libpanorama_text_pango.so
       8542112      9 910d2c486186bd14cddaa4fba94c80310b73d1eb     0 game\bin\linuxsteamrt64\libparticles.so
      40753312     40 6c9c1599c2fc63835fd803388a5e18261ccfd046     0 game\bin\linuxsteamrt64\libphonon.so
       2139308      3 0b9da491c7ed74cf355a224ea4962410643bfc83     0 game\bin\linuxsteamrt64\libpulse_system.so
       3331224      4 d63f0c25084752545bd987c39e6f0ccbfa8ecdb1     0 game\bin\linuxsteamrt64\librendersystemempty.so
       8942884      9 550d5b98dd5d7f705b72d7bfd44855d97a06f2e5     0 game\bin\linuxsteamrt64\librendersystemvulkan.so
        771448      1 88544161c949c1c5638b81e51345a505c2b7f108     0 game\bin\linuxsteamrt64\libresourcesystem.so
       3488632      4 2a6ea2b57964799cc3d8e0664f96bcd1d698de13     0 game\bin\linuxsteamrt64\libscenefilecache.so
      10281884     10 e9ba95ab91986388483c17c9822e6b97c94982cf     0 game\bin\linuxsteamrt64\libscenesystem.so
        696324      1 57dfb4e916182d9cda22bc8f19b6d678a2d2592c     0 game\bin\linuxsteamrt64\libschemasystem.so
       3100368      3 0a470a7030780d22d9a6a7027108988b9ff2bb5f     0 game\bin\linuxsteamrt64\libSDL3.so.0
       7484140      8 8a79cf1beb4caf759f6d87cfc5ffb7c441803e08     0 game\bin\linuxsteamrt64\libsoundsystem.so
       5689772      6 6d134aa2c669ab86fcbb17bccae50df32588f884     0 game\bin\linuxsteamrt64\libsteamaudio.so
       5692434      6 c446696b7bf6cbcaa365d220b23f31efad30be76     0 game\bin\linuxsteamrt64\libsteamnetworkingsockets.so
        381976      1 c109666c839a433b5ff8f635ad173cde77bdcdb6     0 game\bin\linuxsteamrt64\libsteam_api.so
        555448      1 a1191c624317a97fbf634aa13990bc12abd45179     0 game\bin\linuxsteamrt64\libswscale.so.5
       5075900      5 19adce51e35a2cb4136927b8f0d0724736bb26d1     0 game\bin\linuxsteamrt64\libtier0.so
      30769216     30 a3ef228ee95892e08350e73af7a4063d24334c15     0 game\bin\linuxsteamrt64\libv8.so
        464728      1 bd969cd7e25f020d87b13469c2f632faa4fda211     0 game\bin\linuxsteamrt64\libv8system.so
       2926872      3 e84e468c1885ff699fdda290c1aed696b2fcc6cc     0 game\bin\linuxsteamrt64\libv8_icui18n.so
       1916656      2 6c8b6b8683921ef5573a122ca0000399367ede13     0 game\bin\linuxsteamrt64\libv8_icuuc.so
        215240      1 332e13705675ab4f30280f4504d0b6d93f81ce0e     0 game\bin\linuxsteamrt64\libv8_libbase.so
       1172208      2 b22b9ba29bffe328d33c6a1790e5f2b81736bf13     0 game\bin\linuxsteamrt64\libv8_libcpp.so
        113320      1 a4144e9f7d534ba89e1b9dd47de7c636819d43e0     0 game\bin\linuxsteamrt64\libv8_libplatform.so
        110600      1 1f3829ba17a72c8c705b66d0a48bfbd60d9b9e1d     0 game\bin\linuxsteamrt64\libv8_zlib.so
        447104      1 df239bddbe5a0250b6dfbffe91829bed8e6bb818     0 game\bin\linuxsteamrt64\libvconcomm.so
       7032600      7 f892d251c04221fc7e54c32c379a368b8f041bee     0 game\bin\linuxsteamrt64\libvideo.so
        183104      1 236012fc609253612d606f5670749387d751a6eb     0 game\bin\linuxsteamrt64\libvorbis.so.0
        690400      1 b5d3043cadc61cd22fa21ee22eae3546cc7f621b     0 game\bin\linuxsteamrt64\libvorbisenc.so.2
         35360      1 3c4c4fc86877c37c8f637ceae9c91795adfd23d4     0 game\bin\linuxsteamrt64\libvorbisfile.so.3
       5185936      5 4bf6bde99858c06e67bc8bfd4fca100019845fe8     0 game\bin\linuxsteamrt64\libvphysics2.so
       3205768      4 7ee108b86e414426587fcf8d64e037c7f3f78544     0 game\bin\linuxsteamrt64\libvpx.so.6
       1257760      2 7345774849598ddcb37f98cc374d70a483aed24b     0 game\bin\linuxsteamrt64\libvscript.so
       4433276      5 951d13fa0fa04cc2642428c2cac4fec2052c26c6     0 game\bin\linuxsteamrt64\libworldrenderer.so
          3822      1 956919b920713ce452f46c20cf8643674f7543f7     0 game\cs2.sh
      71667480     69 4980f06fe0e6ba11ec7c2990e7a72943db8c9ba8     0 game\csgo\bin\linuxsteamrt64\libclient.so
       3003124      3 4b71c1fb313231abd87e6755d85cad9c55450245     0 game\csgo\bin\linuxsteamrt64\libhost.so
       3647508      4 67fa224d009688c54ecf3797733ead37b6635964     0 game\csgo\bin\linuxsteamrt64\libmatchmaking.so
      39212728     38 11341e9fd59a71a7de7b147ca33c8c92d5bd41af     0 game\csgo\bin\linuxsteamrt64\libserver.so
     105109214    108 88adb58ebbb943bc55b25df282873a064f6606ce     0 game\csgo_community_addons\cs_alpine\cs_alpine_000.vpk
     108929206    111 900d9f375ba2e320a8c945ef2364d54b7846b85a     0 game\csgo_community_addons\cs_alpine\cs_alpine_001.vpk
     106746135    108 688be350d5145aae831ac6b682b95b801eefc0d6     0 game\csgo_community_addons\cs_alpine\cs_alpine_002.vpk
     105831104    106 b89458e4263c26a05f799d7bee735cb4c85bb11d     0 game\csgo_community_addons\cs_alpine\cs_alpine_003.vpk
     107055567    112 572c49b81c03920af3aa01c0199d5c78d3881bd0     0 game\csgo_community_addons\cs_alpine\cs_alpine_004.vpk
     106911144    111 89dd1103ad0dd6ae06ffcb5d6f3b366f00ebe126     0 game\csgo_community_addons\cs_alpine\cs_alpine_005.vpk
     109845126    117 48f628aaef08460470ccb57dc48268c8b4f524b5     0 game\csgo_community_addons\cs_alpine\cs_alpine_006.vpk
     105575056    105 0172409752d1d4db697083a9812a4357a1e097b5     0 game\csgo_community_addons\cs_alpine\cs_alpine_007.vpk
     106322750    112 2cce54f91d8008f1dc013e4e99a7347d6b0f5108     0 game\csgo_community_addons\cs_alpine\cs_alpine_008.vpk
     105656344    111 7297bdf1f663a51434387ea323aa93a5bc8ee186     0 game\csgo_community_addons\cs_alpine\cs_alpine_009.vpk
     120309236    123 389285ffe9f83e79f74bf22c82d43ca4cfed65f5     0 game\csgo_community_addons\cs_alpine\cs_alpine_010.vpk
     106299152    111 4d93673c146e7cd1f79c75d1bc57bfb68269e157     0 game\csgo_community_addons\cs_alpine\cs_alpine_011.vpk
     104945248    114 63d0f36f2076ff71ab4125a613452021f10f69f7     0 game\csgo_community_addons\cs_alpine\cs_alpine_012.vpk
     107092492    111 bb2728a5eefd159ef1b14972b2ec0998ed2a7dbd     0 game\csgo_community_addons\cs_alpine\cs_alpine_013.vpk
     106382332    109 435db0f2e59edd0608257a0a618033d24a09142f     0 game\csgo_community_addons\cs_alpine\cs_alpine_014.vpk
     106435024    113 08103400d2c7ccfa3cf86806301eea6daab8f853     0 game\csgo_community_addons\cs_alpine\cs_alpine_015.vpk
     105735857    111 814c1ece29d49bb03d14b3f70446a82f2cb78145     0 game\csgo_community_addons\cs_alpine\cs_alpine_016.vpk
     107715082    112 3d63b64447b0cc154dd39ce645e7b9b330473154     0 game\csgo_community_addons\cs_alpine\cs_alpine_017.vpk
     105741486    110 0f37467b4c5a401b1f01b76ff1a877c1c6e65b4f     0 game\csgo_community_addons\cs_alpine\cs_alpine_018.vpk
      68574180     66 1277b64258e1cd00b40c4d3d612ac1661da17e1c     0 game\csgo_community_addons\cs_alpine\cs_alpine_019.vpk
        126482      1 88e58a2beb82fd92a668d3520ec826a45446a77d     0 game\csgo_community_addons\cs_alpine\cs_alpine_dir.vpk
     104986147    102 f27723fc3e7de8002d875ef29ac3f6fea321bdb5     0 game\csgo_community_addons\de_poseidon\de_poseidon_000.vpk
     107170728    104 df130376866b34df682f0d9fd39c2c956fcf3a31     0 game\csgo_community_addons\de_poseidon\de_poseidon_001.vpk
     105640796    103 a83ca2cd21d173539a646b3943f45e4505e855b9     0 game\csgo_community_addons\de_poseidon\de_poseidon_002.vpk
      90242021     88 ca054905e3fd87f103c9c95dc2455b2b51aff7e2     0 game\csgo_community_addons\de_poseidon\de_poseidon_003.vpk
         24357      1 dd526a07922c4004c5316b9d3b79677d9f8999fe     0 game\csgo_community_addons\de_poseidon\de_poseidon_dir.vpk
     107923616    112 7f4ef5cd2456e5994ead14e482cec00b97336876     0 game\csgo_community_addons\de_sanctum\de_sanctum_000.vpk
     108080581    111 e0dc4614e8ad579028fb1142dc087ad6b9d007f9     0 game\csgo_community_addons\de_sanctum\de_sanctum_001.vpk
     127183947    130 42590add17a0b615558bb2179167d3101d5150cb     0 game\csgo_community_addons\de_sanctum\de_sanctum_002.vpk
     105939600    109 a90345e76144a71833f699edcd0dffb79ab504fc     0 game\csgo_community_addons\de_sanctum\de_sanctum_003.vpk
     106111735    108 c5bbfce28523f056d91a6799f8d092cab8b8009f     0 game\csgo_community_addons\de_sanctum\de_sanctum_004.vpk
     108914134    112 155a4ac074fe5c8fbb32287481aab08b8bb97be1     0 game\csgo_community_addons\de_sanctum\de_sanctum_005.vpk
     104938940    107 bbc9e0c728b1d8001166862499f54e2f1d97e882     0 game\csgo_community_addons\de_sanctum\de_sanctum_006.vpk
     105259404    110 9feb7422ce8ce342794c43fc4a962d9bc678748b     0 game\csgo_community_addons\de_sanctum\de_sanctum_007.vpk
     109189519    117 aab3e0b1c6c0c7da3ff32c540eaa6eb97a6f9830     0 game\csgo_community_addons\de_sanctum\de_sanctum_008.vpk
     110199602    117 d8ab9e6f0c3e2d0ae11f4119f4f22aaa99e34b07     0 game\csgo_community_addons\de_sanctum\de_sanctum_009.vpk
     108059910    107 2b31ed669dbf741000ddbc8c359a14ca287e27e4     0 game\csgo_community_addons\de_sanctum\de_sanctum_010.vpk
     105896131    111 f26d17fc6d63c8d7cbcd0997b1574be8250d6f9f     0 game\csgo_community_addons\de_sanctum\de_sanctum_011.vpk
      78884376     78 c57156e52a8fbf88ad9856b87367c92cf6c68889     0 game\csgo_community_addons\de_sanctum\de_sanctum_012.vpk
        109160      1 27b0b56c9b10f62c93e9d4db964bfe47bed52069     0 game\csgo_community_addons\de_sanctum\de_sanctum_dir.vpk
     109773350    110 f15fbafb318fa500270c81f15afcda4b4281d647     0 game\csgo_community_addons\de_stronghold\de_stronghold_000.vpk
     124501876    123 6b2cb15eb2ce574e8eafd071a5bce49ca9683514     0 game\csgo_community_addons\de_stronghold\de_stronghold_001.vpk
     107885992    108 9d64227e4dee4dcf0286b46abf55fdee6b91a19b     0 game\csgo_community_addons\de_stronghold\de_stronghold_002.vpk
     104955620    103 b48813c5db0aaeb7b75415b52b0829502e9e58f0     0 game\csgo_community_addons\de_stronghold\de_stronghold_003.vpk
     107232168    104 97ca11de79cb9bdebc0e0e34136d2c6bde05eafc     0 game\csgo_community_addons\de_stronghold\de_stronghold_004.vpk
     106319860    108 135968c4d60e8218a9ebd4313ea22f454d6c428a     0 game\csgo_community_addons\de_stronghold\de_stronghold_005.vpk
     106328092    106 e4b423c04772961a4b002da0e43c7968d7008e9e     0 game\csgo_community_addons\de_stronghold\de_stronghold_006.vpk
     105976232    106 1c538cc0b100ce3874459842ca56b6f9f9caa7d5     0 game\csgo_community_addons\de_stronghold\de_stronghold_007.vpk
     105374374    103 b877fc7396a13a51ba5738e308e3ace05b822119     0 game\csgo_community_addons\de_stronghold\de_stronghold_008.vpk
     105006606    102 103b857e5e049806d537a491ee5d61a242bee563     0 game\csgo_community_addons\de_stronghold\de_stronghold_009.vpk
     120975005    118 24e70a017e75de0ef08425a2d09ab0091416a203     0 game\csgo_community_addons\de_stronghold\de_stronghold_010.vpk
     104870986    102 33c1afea3dce0b9e51beca1410bc89540ec9048a     0 game\csgo_community_addons\de_stronghold\de_stronghold_011.vpk
     116964132    116 7f82cc3eb4028a52a2e765627b28f5d413945bc1     0 game\csgo_community_addons\de_stronghold\de_stronghold_012.vpk
     107400297    105 fb460ab77d0ed17faa515506a8c3719673b8f60c     0 game\csgo_community_addons\de_stronghold\de_stronghold_013.vpk
     104071041    103 19defdf2bb42703f39c21ced2ecf0f847f4959c3     0 game\csgo_community_addons\de_stronghold\de_stronghold_014.vpk
        121060      1 12128786e524fec64407a51d2b63285a6298b504     0 game\csgo_community_addons\de_stronghold\de_stronghold_dir.vpk
     108021069    106 2f20647b4c6591b2e08591ea8ba421f8c2a8afee     0 game\csgo_community_addons\de_warden\de_warden_000.vpk
     110304770    109 98c682684f9e7a58c20a2ab3121ee855170264f6     0 game\csgo_community_addons\de_warden\de_warden_001.vpk
     106372627    105 4a7b57edffffaaba5791b7663500219fe7398aef     0 game\csgo_community_addons\de_warden\de_warden_002.vpk
     106511500    104 12c16a0e6dffa7df0958fef71b58528ac69843aa     0 game\csgo_community_addons\de_warden\de_warden_003.vpk
     108053470    108 db1e2fade242e1351c3044338edb0ae8665e28bd     0 game\csgo_community_addons\de_warden\de_warden_004.vpk
     104964150    102 84468463e9094b1a65be5b320a04e15033a99bb1     0 game\csgo_community_addons\de_warden\de_warden_005.vpk
     109960457    107 59b1c407a625633bbf5c257e6fee8cbc7a090074     0 game\csgo_community_addons\de_warden\de_warden_006.vpk
     105661423    107 a15915ec1237ab1a9ad81a28f5ef1296b7a37812     0 game\csgo_community_addons\de_warden\de_warden_007.vpk
     106334767    104 5821c2c87e541c72c957c779ef4c20952dfdfb3b     0 game\csgo_community_addons\de_warden\de_warden_008.vpk
     106293529    105 e5e90a354537b498393b93dbca5ba668ece2ddad     0 game\csgo_community_addons\de_warden\de_warden_009.vpk
     105462767    102 e05f0287e83790f7ff483d00a0fd9ea2f7c8d314     0 game\csgo_community_addons\de_warden\de_warden_010.vpk
     109331645    105 81f9c389717d29fd9ba5e1e8117395a5a4fb368c     0 game\csgo_community_addons\de_warden\de_warden_011.vpk
     108943601    107 11fca34f7e473c18ea7c548bc5c95c51b1f87ef1     0 game\csgo_community_addons\de_warden\de_warden_012.vpk
      45637976     45 f3ab81339d489c9ad77ce7a6a694e00af3a57cab     0 game\csgo_community_addons\de_warden\de_warden_013.vpk
         97137      1 d83e192edd2863ada18dd9926a7a97e683bbb459     0 game\csgo_community_addons\de_warden\de_warden_dir.vpk

```

use `-filelist` to download only `game\csgo\steam.inf` when downloading `-depot 2347770` , see https://github.com/SteamRE/DepotDownloader and https://github.com/SteamRE/DepotDownloader/blob/master/DepotDownloader/Program.cs#L107 for usage.

从`steam.inf`提取PatchVersion作为版本号

```
ClientVersion=2000777
ServerVersion=2000777
PatchVersion=1.41.4.1
ProductName=cs2
appID=730
ServerAppID=2347773
SourceRevision=10575829
VersionDate=Apr 02 2026
VersionTime=15:07:02
```

版本创建规则：

1. 如果PatchVersion对应的版本(1.41.6.1->14161) 在download.yaml里不存在：

更新download.yaml，追加：

```
  - tag: "14161"
    name: 1.41.6.1
    manifests: 
     "2347771" : "6999933698852825529" # 这里填 DepotDownloader -app 730 -depot 2347771 -os all-platform -dir cs2_depot -manifest-only 生成的manifest id
     "2347773" : "1005161166845732962" # 这里填 DepotDownloader -app 730 -depot 2347773 -os all-platform -dir cs2_depot -manifest-only 生成的manifest id
```

2. 如果PatchVersion对应的版本在download.yaml里已经存在，但是2347771或2347773对应的manifestid存在变化：

更新download.yaml，追加：

```
  - tag: "14161b"
    name: 1.41.6.1
    manifests: 
     "2347771" : "6999933698852825529"
     "2347773" : "1005161166845732962"
```

3. 如果PatchVersion对应的版本在download.yaml里已经存在，且2347771和2347773对应的manifestid都和download.yaml已经存在的项相同，则视为游戏没有更新，不做任何事情。

更新完download.yaml之后，调用git命令创建对应tag并提交。