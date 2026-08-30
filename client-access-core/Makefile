include $(TOPDIR)/rules.mk

PKG_NAME:=client-access-core
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Client Access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

CLIENT_ACCESS_REPO_DIR:=$(patsubst %/,%,$(dir $(realpath $(CURDIR))))

include $(INCLUDE_DIR)/package.mk

define Package/client-access-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Headless identity-based LAN Internet access control
  DEPENDS:=+firewall4 +nftables-json +ucode +ucode-mod-fs +ucode-mod-ubus \
	+ucode-mod-uci +ucode-mod-uloop
endef

define Package/client-access-core/description
 Headless Client Access control plane and nftables datapath for OpenWrt and
 ImmortalWrt. LuCI and the TC eBPF backend are optional clients of this package.
endef

define Package/client-access-core/conffiles
/etc/config/client_access
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/root $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/client-access-core/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/root/etc/config/client_access $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/client-access $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface $(1)/etc/hotplug.d/ntp
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/hotplug.d/iface/90-client-access \
		$(1)/etc/hotplug.d/iface/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/hotplug.d/ntp/90-client-access \
		$(1)/etc/hotplug.d/ntp/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/usr/sbin/client-accessd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/share/ucode/client_access
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/ucode/client_access/*.uc \
		$(1)/usr/share/ucode/client_access/
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/table-pre
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/nftables.d/table-pre/30-client-access.nft \
		$(1)/usr/share/nftables.d/table-pre/
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/forward
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft \
		$(1)/usr/share/nftables.d/chain-pre/forward/
endef

define Package/client-access-core/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/etc/init.d/client-access enable >/dev/null 2>&1 || true
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

define Package/client-access-core/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/etc/init.d/client-access stop >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,client-access-core))
