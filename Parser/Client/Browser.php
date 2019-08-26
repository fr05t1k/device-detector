<?php declare(strict_types=1);

/**
 * Device Detector - The Universal Device Detection library for parsing User Agents
 *
 * @link http://piwik.org
 *
 * @license http://www.gnu.org/licenses/lgpl.html LGPL v3 or later
 */

namespace DeviceDetector\Parser\Client;

use DeviceDetector\Parser\Client\Browser\Engine;

/**
 * Class Browser
 *
 * Client parser for browser detection
 */
class Browser extends AbstractClientParser
{
    /**
     * @var string
     */
    protected $fixtureFile = 'regexes/client/browsers.yml';

    /**
     * @var string
     */
    protected $parserName = 'browser';

    /**
     * Known browsers
     *
     * @var array
     */
    protected static $availableBrowsers = [
        '2345 Browser',
        '360 Phone Browser',
        '360 Browser',
        'Avant Browser',
        'ABrowse',
        'ANT Fresco',
        'ANTGalio',
        'Aloha Browser',
        'Amaya',
        'Amigo',
        'Android Browser',
        'AOL Shield',
        'Arora',
        'Amiga Voyager',
        'Amiga Aweb',
        'Atomic Web Browser',
        'Avast Secure Browser',
        'Beaker Browser',
        'BlackBerry Browser',
        'Baidu Browser',
        'Baidu Spark',
        'Basilisk',
        'Beonex',
        'Bunjalloo',
        'B-Line',
        'Brave',
        'BriskBard',
        'BrowseX',
        'Camino',
        'Coc Coc',
        'Comodo Dragon',
        'Coast',
        'Charon',
        'CM Browser',
        'Chrome Frame',
        'Headless Chrome',
        'Chrome',
        'Chrome Mobile iOS',
        'Conkeror',
        'Chrome Mobile',
        'CoolNovo',
        'CometBird',
        'ChromePlus',
        'Chromium',
        'Cyberfox',
        'Cheshire',
        'Cunaguaro',
        'Chrome Webview',
        'dbrowser',
        'Deepnet Explorer',
        'Dolphin',
        'Dorado',
        'Dooble',
        'Dillo',
        'DuckDuckGo Privacy Browser',
        'Ecosia',
        'Epic',
        'Elinks',
        'Element Browser',
        'GNOME Web',
        'Espial TV Browser',
        'Firefox Mobile iOS',
        'Firebird',
        'Fluid',
        'Fennec',
        'Firefox',
        'Firefox Focus',
        'Firefox Rocket',
        'Flock',
        'Firefox Mobile',
        'Fireweb',
        'Fireweb Navigator',
        'FreeU',
        'Galeon',
        'Google Earth',
        'Hawk Turbo Browser',
        'hola! Browser',
        'HotJava',
        'Huawei Browser',
        'IBrowse',
        'iCab',
        'iCab Mobile',
        'Iridium',
        'Iron Mobile',
        'IceCat',
        'IceDragon',
        'Isivioo',
        'Iceweasel',
        'Internet Explorer',
        'IE Mobile',
        'Iron',
        'Jasmine',
        'Jig Browser',
        'Jio Browser',
        'K.Browser',
        'Kindle Browser',
        'K-meleon',
        'Konqueror',
        'Kapiko',
        'Kiwi',
        'Kylo',
        'Kazehakase',
        'Cheetah Browser',
        'LieBaoFast',
        'LG Browser',
        'Links',
        'LuaKit',
        'Lunascape',
        'Lynx',
        'MicroB',
        'NCSA Mosaic',
        'Mercury',
        'Mobile Safari',
        'Midori',
        'Mobicip',
        'MIUI Browser',
        'Mobile Silk',
        'Mint Browser',
        'Maxthon',
        'Nokia Browser',
        'Nokia OSS Browser',
        'Nokia Ovi Browser',
        'Nox Browser',
        'NetSurf',
        'NetFront',
        'NetFront Life',
        'NetPositive',
        'Netscape',
        'NTENT Browser',
        'Oculus Browser',
        'Opera Mini iOS',
        'Obigo',
        'Odyssey Web Browser',
        'Off By One',
        'ONE Browser',
        'Opera Neon',
        'Opera Devices',
        'Opera Mini',
        'Opera Mobile',
        'Opera',
        'Opera Next',
        'Opera Touch',
        'Oregano',
        'Openwave Mobile Browser',
        'OmniWeb',
        'Otter Browser',
        'Palm Blazer',
        'Pale Moon',
        'Oppo Browser',
        'Palm Pre',
        'Puffin',
        'Palm WebPro',
        'Palmscape',
        'Phoenix',
        'Polaris',
        'Polarity',
        'Microsoft Edge',
        'QQ Browser Mini',
        'QQ Browser',
        'Qutebrowser',
        'QupZilla',
        'Qwant Mobile',
        'QtWebEngine',
        'Realme Browser',
        'Rekonq',
        'RockMelt',
        'Samsung Browser',
        'Sailfish Browser',
        'SEMC-Browser',
        'Sogou Explorer',
        'Safari',
        'Shiira',
        'Skyfire',
        'Seraphic Sraf',
        'Sleipnir',
        'Snowshoe',
        'Sogou Mobile Browser',
        'Sputnik Browser',
        'Sunrise',
        'SuperBird',
        'Streamy',
        'Swiftfox',
        'Seznam Browser',
        'TenFourFox',
        'Tenta Browser',
        'Tizen Browser',
        'TweakStyle',
        'UC Browser',
        'UC Browser Mini',
        'Vivaldi',
        'vivo Browser',
        'Vision Mobile Browser',
        'Web Explorer',
        'WebPositive',
        'Waterfox',
        'Whale Browser',
        'wOSBrowser',
        'WeTab Browser',
        'Yandex Browser',
        'Xiino',

        // detected browsers in older versions
        // 'Iceape',  => pim
        // 'SeaMonkey',  => pim
    ];

    /**
     * Browser families mapped to the associated browsers
     *
     * @var array
     */
    protected static $browserFamilies = [
        'Android Browser'    => ['Android Browser', 'MIUI Browser'],
        'BlackBerry Browser' => ['BlackBerry Browser'],
        'Baidu'              => ['Baidu Browser', 'Baidu Spark'],
        'Amiga'              => ['Amiga Voyager', 'Amiga Aweb'],
        'Chrome'             => [
            'Chrome', 'Beaker Browser', 'Brave', 'Coc Coc', 'Comodo Dragon', 'Chrome Mobile', 'Chrome Mobile iOS',
            'Chrome Frame', 'CoolNovo', 'Chromium', 'ChromePlus', 'Iron', 'RockMelt', 'Amigo', 'TweakStyle', 'Vivaldi',
            'Polarity', 'Avast Secure Browser', 'Tenta Browser', 'AOL Shield', 'Samsung Browser', 'Web Explorer',
            'Iron Mobile', 'Chrome Webview', 'Whale Browser', 'Seznam Browser', 'QtWebEngine', 'LieBaoFast', 'Kiwi',
            '2345 Browser', 'CM Browser', 'Ecosia', 'Mint Browser', 'Mobile Silk', 'DuckDuckGo Privacy Browser', 'Mobile Silk', 'Hawk Turbo Browser', 'Oculus Browser',
        ],
        'Firefox'            => [
            'Firefox', 'Fennec', 'Firefox Mobile', 'Swiftfox', 'Firebird', 'Phoenix', 'MicroB', 'Epic', 'Waterfox',
            'Cunaguaro', 'TenFourFox', 'Qwant Mobile', 'Firefox Rocket', 'IceCat', 'Mobicip', 'Firefox Mobile iOS', 'Basilisk',
        ],
        'Internet Explorer'  => ['Internet Explorer', 'IE Mobile', 'Microsoft Edge'],
        'Konqueror'          => ['Konqueror'],
        'NetFront'           => ['NetFront'],
        'NetSurf'            => ['NetSurf'],
        'Nokia Browser'      => ['Nokia Browser', 'Nokia OSS Browser', 'Nokia Ovi Browser', 'Dorado'],
        'Opera'              => [
            'Opera', 'Opera Mobile', 'Opera Mini', 'Opera Next', 'Opera Touch', 'Opera Neon', 'Opera Devices',
            'Opera Mini iOS'
        ],
        'Safari'             => ['Safari', 'Mobile Safari', 'Sogou Mobile Browser'],
        'Sailfish Browser'   => ['Sailfish Browser'],
    ];

    /**
     * Browsers that are available for mobile devices only
     *
     * @var array
     */
    protected static $mobileOnlyBrowsers = [
        '360 Phone Browser', 'Oculus Browser', 'Puffin', 'Skyfire', 'Mobile Safari', 'Opera Mini', 'Opera Mobile',
        'dbrowser', 'Streamy', 'B-Line', 'Isivioo', 'Firefox Mobile', 'Coast', 'Aloha Browser',
        'Sailfish Browser', 'Samsung Browser', 'Firefox Rocket', 'Web Explorer', 'DuckDuckGo Privacy Browser',
        'Hawk Turbo Browser', 'Nox Browser', 'Huawei Browser', 'vivo Browser', 'Realme Browser',
    ];

    /**
     * Returns list of all available browsers
     * @return array
     */
    public static function getAvailableBrowsers(): array
    {
        return self::$availableBrowsers;
    }

    /**
     * Returns list of all available browser families
     * @return array
     */
    public static function getAvailableBrowserFamilies(): array
    {
        return self::$browserFamilies;
    }


    /**
     * @param string $browserName
     *
     * @return string|null If null, "Unknown"
     */
    public static function getBrowserFamily(string $browserName): ?string
    {
        foreach (self::$browserFamilies as $browserFamily => $browserNames) {
            if (in_array($browserName, $browserNames)) {
                return $browserFamily;
            }
        }

        return null;
    }

    /**
     * Returns if the given browser is mobile only
     *
     * @param string $browser Name of browser
     *
     * @return bool
     */
    public static function isMobileOnlyBrowser(string $browser): bool
    {
        return in_array($browser, self::$mobileOnlyBrowsers);
    }

    /**
     * @inheritdoc
     */
    public function parse(): ?array
    {
        foreach ($this->getRegexes() as $regex) {
            $matches = $this->matchUserAgent($regex['regex']);

            if ($matches) {
                break;
            }
        }

        if (empty($matches) || empty($regex)) {
            return null;
        }

        $name = $this->buildByMatch($regex['name'], $matches);

        foreach (self::getAvailableBrowsers() as $browserName) {
            if (strtolower($name) === strtolower($browserName)) {
                $version       = $this->buildVersion((string) $regex['version'], $matches);
                $engine        = $this->buildEngine($regex['engine'] ?? [], $version);
                $engineVersion = $this->buildEngineVersion($engine);

                return [
                    'type'           => 'browser',
                    'name'           => $browserName,
                    'version'        => $version,
                    'engine'         => $engine,
                    'engine_version' => $engineVersion,
                ];
            }
        }

        // This Exception should never be thrown. If so a defined browser name is missing in $availableBrowsers
        throw new \Exception(sprintf('Detected browser name "%s" was not found in $availableBrowsers. Tried to parse user agent: %s', $name, $this->userAgent)); // @codeCoverageIgnore
    }

    /**
     * @param array  $engineData
     * @param string $browserVersion
     *
     * @return string
     */
    protected function buildEngine(array $engineData, string $browserVersion): string
    {
        $engine = '';

        // if an engine is set as default
        if (isset($engineData['default'])) {
            $engine = $engineData['default'];
        }

        // check if engine is set for browser version
        if (array_key_exists('versions', $engineData) && is_array($engineData['versions'])) {
            foreach ($engineData['versions'] as $version => $versionEngine) {
                if (version_compare($browserVersion, (string) $version) < 0) {
                    continue;
                }

                $engine = $versionEngine;
            }
        }

        // try to detect the engine using the regexes
        if (empty($engine)) {
            $engineParser = new Engine();
            $engineParser->setYamlParser($this->getYamlParser());
            $engineParser->setCache($this->getCache());
            $engineParser->setUserAgent($this->userAgent);
            $result = $engineParser->parse();
            $engine = $result['engine'] ?? '';
        }

        return $engine;
    }

    /**
     * @param string $engine
     *
     * @return string
     */
    protected function buildEngineVersion(string $engine): string
    {
        $engineVersionParser = new Engine\Version($this->userAgent, $engine);

        $result = $engineVersionParser->parse();

        return $result['version'] ?? '';
    }
}
