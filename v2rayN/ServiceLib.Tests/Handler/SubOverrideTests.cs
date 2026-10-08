using ServiceLib.Handler;

namespace ServiceLib.Tests.Handler;

public class SubOverrideTests
{
    private static ProfileItem CreateProfile() => new()
    {
        ConfigType = EConfigType.VLESS,
        Address = "188.114.97.3",
        Port = 443,
    };

    [Test]
    public async Task ApplySubOverrides_ShouldReplaceAddressAndPort()
    {
        var profile = CreateProfile();

        ConfigHandler.ApplySubOverrides(profile, new SubItem { OverrideAddress = "example.com", OverridePort = 8443 });

        await profile.Address.Should().BeEqualTo("example.com");
        await profile.Port.Should().BeEqualTo(8443);
    }

    [Test]
    public async Task ApplySubOverrides_ShouldReplaceOnlyTheConfiguredValue()
    {
        var addressOnly = CreateProfile();
        ConfigHandler.ApplySubOverrides(addressOnly, new SubItem { OverrideAddress = "example.com" });
        await addressOnly.Address.Should().BeEqualTo("example.com");
        await addressOnly.Port.Should().BeEqualTo(443);

        var portOnly = CreateProfile();
        ConfigHandler.ApplySubOverrides(portOnly, new SubItem { OverridePort = 8443 });
        await portOnly.Address.Should().BeEqualTo("188.114.97.3");
        await portOnly.Port.Should().BeEqualTo(8443);
    }

    [Test]
    public async Task ApplySubOverrides_ShouldKeepProfileWhenNothingIsConfigured()
    {
        SubItem?[] subItems =
        [
            null,
            new SubItem(),
            new SubItem { OverrideAddress = "   ", OverridePort = 0 },
            new SubItem { OverridePort = 70000 },
        ];

        foreach (var subItem in subItems)
        {
            var profile = CreateProfile();

            ConfigHandler.ApplySubOverrides(profile, subItem);

            await profile.Address.Should().BeEqualTo("188.114.97.3");
            await profile.Port.Should().BeEqualTo(443);
        }
    }

    [Test]
    public async Task ApplySubOverrides_ShouldTrimAddress()
    {
        var profile = CreateProfile();

        ConfigHandler.ApplySubOverrides(profile, new SubItem { OverrideAddress = " example.com " });

        await profile.Address.Should().BeEqualTo("example.com");
    }

    [Test]
    public async Task ApplySubOverrides_WhenSniBlockBypassEnabledGlobally_ShouldApplyEvasionSettingsToTlsProfile()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.Should().BeEqualTo(Global.FingerprintUnsafe);
        await profile.CipherSuites.Should().BeEqualTo(Global.DefaultSniBlockBypassCipherSuites);
        await profile.Finalmask.IsNotEmpty().Should().BeTrue();

        var node = JsonUtils.ParseJson(profile.Finalmask);
        await (node is JsonObject).Should().BeTrue();
    }

    [Test]
    public async Task ApplySubOverrides_WhenSniBlockBypassEnabledGlobally_ShouldApplyEvasionSettingsToRealityProfile()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurityReality;
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.Should().BeEqualTo("chrome");
        await profile.CipherSuites.IsNullOrEmpty().Should().BeTrue();
        await profile.Finalmask.IsNotEmpty().Should().BeTrue();
    }

    [Test]
    public async Task ApplySubOverrides_WhenSniBlockBypassEnabled_ShouldNotApplyEvasionToNonTlsProfile()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = string.Empty;
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.IsNullOrEmpty().Should().BeTrue();
        await profile.CipherSuites.IsNullOrEmpty().Should().BeTrue();
        await profile.Finalmask.IsNullOrEmpty().Should().BeTrue();
    }

    [Test]
    public async Task ApplySubOverrides_WhenTrojanProfileWithoutExplicitStreamSecurity_ShouldApplyEvasion()
    {
        var profile = CreateProfile();
        profile.ConfigType = EConfigType.Trojan;
        profile.StreamSecurity = string.Empty;
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.Should().BeEqualTo(Global.FingerprintUnsafe);
        await profile.CipherSuites.Should().BeEqualTo(Global.DefaultSniBlockBypassCipherSuites);
        await profile.Finalmask.IsNotEmpty().Should().BeTrue();
    }

    [Test]
    public async Task ApplySubOverrides_WhenProfileHasChromeFingerprint_ShouldOverrideToUnsafe()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        profile.Fingerprint = "chrome";
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.Should().BeEqualTo(Global.FingerprintUnsafe);
    }

    [Test]
    public async Task ApplySubOverrides_WhenProfileHasCustomFingerprint_ShouldPreserveIt()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        profile.Fingerprint = "firefox";
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.Fingerprint.Should().BeEqualTo("firefox");
    }

    [Test]
    public async Task ApplySubOverrides_WhenProfileHasCustomCipherSuitesAndFinalmask_ShouldPreserveThem()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        profile.CipherSuites = "CUSTOM_CIPHER";
        profile.Finalmask = "{\"custom\":true}";
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, null, config);

        await profile.CipherSuites.Should().BeEqualTo("CUSTOM_CIPHER");
        await profile.Finalmask.Should().BeEqualTo("{\"custom\":true}");
    }

    [Test]
    public async Task ApplySubOverrides_WhenSubItemForcesEnable_ShouldApplyEvenIfGlobalIsDisabled()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        var subItem = new SubItem { SniBlockBypass = true };
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = false },
        };

        ConfigHandler.ApplySubOverrides(profile, subItem, config);

        await profile.Fingerprint.Should().BeEqualTo(Global.FingerprintUnsafe);
        await profile.CipherSuites.Should().BeEqualTo(Global.DefaultSniBlockBypassCipherSuites);
        await profile.Finalmask.IsNotEmpty().Should().BeTrue();
    }

    [Test]
    public async Task ApplySubOverrides_WhenSubItemForcesDisable_ShouldNotApplyEvenIfGlobalIsEnabled()
    {
        var profile = CreateProfile();
        profile.StreamSecurity = Global.StreamSecurity;
        var subItem = new SubItem { SniBlockBypass = false };
        var config = new Config
        {
            CoreBasicItem = new() { EnableSubSniBlockBypass = true },
        };

        ConfigHandler.ApplySubOverrides(profile, subItem, config);

        await profile.Fingerprint.IsNullOrEmpty().Should().BeTrue();
        await profile.CipherSuites.IsNullOrEmpty().Should().BeTrue();
        await profile.Finalmask.IsNullOrEmpty().Should().BeTrue();
    }

    [Test]
    public async Task BuildDefaultFragmentFinalmask_ShouldProduceValidJsonObjectWithTcpFragment()
    {
        var finalmaskJson = ConfigHandler.BuildDefaultFragmentFinalmask();
        var node = JsonUtils.ParseJson(finalmaskJson);

        await (node is JsonObject).Should().BeTrue();
        var jsonObj = (JsonObject)node!;
        await (jsonObj["tcp"] is JsonArray).Should().BeTrue();
        var tcpArray = (JsonArray)jsonObj["tcp"]!;
        await tcpArray.Count.Should().BeGreaterThan(0);
    }
}
