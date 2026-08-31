include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-client-access
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Client Access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=luci-base/host

CLIENT_ACCESS_REPO_DIR:=$(patsubst %/,%,$(dir $(realpath $(CURDIR))))
include $(CLIENT_ACCESS_REPO_DIR)/version.mk

PKG_VERSION:=$(CLIENT_ACCESS_VERSION)
PKG_RELEASE:=$(CLIENT_ACCESS_RELEASE)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-client-access
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI frontend for Client Access
  DEPENDS:=+client-access-core +luci-base +rpcd +rpcd-mod-ucode
endef

define Package/luci-app-client-access/description
 Web frontend for the headless Client Access control plane.
endef

define Package/luci-i18n-client-access-zh-cn
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=luci-app-client-access - zh-cn translation
  HIDDEN:=1
  DEFAULT:=LUCI_LANG_zh_Hans||(ALL&&m)
  DEPENDS:=+luci-app-client-access
  PKGARCH:=all
endef

define Package/luci-i18n-client-access-zh-cn/description
 Simplified Chinese translation for luci-app-client-access.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/htdocs $(PKG_BUILD_DIR)/
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/po $(PKG_BUILD_DIR)/
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/root $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/luci-app-client-access/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/client-access
	$(CP) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/client-access/* \
		$(1)/www/luci-static/resources/view/client-access/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/client-access
	$(CP) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/client-access/* \
		$(1)/www/luci-static/resources/client-access/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-client-access.json \
		$(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/rpcd/acl.d/luci-app-client-access.json \
		$(1)/usr/share/rpcd/acl.d/
endef

define Package/luci-app-client-access/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
endef

define Package/luci-app-client-access/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
endef

define Package/luci-i18n-client-access-zh-cn/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	echo "uci set luci.languages.zh_cn='简体中文 (Simplified Chinese)'; uci commit luci" \
		> $(1)/etc/uci-defaults/luci-i18n-client-access-zh-cn
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(STAGING_DIR_HOSTPKG)/bin/po2lmo \
		$(PKG_BUILD_DIR)/po/zh_Hans/client-access.po \
		$(1)/usr/lib/lua/luci/i18n/client-access.zh-cn.lmo
endef

$(eval $(call BuildPackage,luci-app-client-access))
$(eval $(call BuildPackage,luci-i18n-client-access-zh-cn))
