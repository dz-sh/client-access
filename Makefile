include $(TOPDIR)/rules.mk

LUCI_TITLE:=LAN client Internet access policy
LUCI_DEPENDS:=+luci-base +firewall4 +nftables-json +rpcd +rpcd-mod-ucode +ucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-uloop
LUCI_PKGARCH:=all
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=luci-app-client-access contributors

define Package/luci-app-client-access/conffiles
/etc/config/client_access
endef

define Package/luci-app-client-access/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
	/etc/init.d/client-access enable >/dev/null 2>&1 || true
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
