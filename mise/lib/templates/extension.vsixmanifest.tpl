<?xml version="1.0" encoding="utf-8"?>
	<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
		<Metadata>
			<Identity Language="en-US" Id="%s" Version="%s" Publisher="%s" />
			<DisplayName>%s</DisplayName>
			<Description xml:space="preserve">%s</Description>
			<Tags>%s</Tags>
			<Categories>%s</Categories>
			<GalleryFlags>Public</GalleryFlags>

			<Properties>
				<Property Id="Microsoft.VisualStudio.Code.Engine" Value="%s" />
				<Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
				<Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
				<Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
				<Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />

				<Property Id="Microsoft.VisualStudio.Services.Links.Source" Value="" />
				<Property Id="Microsoft.VisualStudio.Services.Links.Getstarted" Value="" />
				<Property Id="Microsoft.VisualStudio.Services.Links.GitHub" Value="" />
				<Property Id="Microsoft.VisualStudio.Services.Links.Support" Value="" />
				<Property Id="Microsoft.VisualStudio.Services.Links.Learn" Value="" />
				<Property Id="Microsoft.VisualStudio.Services.Branding.Color" Value="#F2F2F2" />
				<Property Id="Microsoft.VisualStudio.Services.Branding.Theme" Value="light" />
				<Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
				<Property Id="Microsoft.VisualStudio.Services.Content.Pricing" Value="Free"/>
			</Properties>%s%s
		</Metadata>
		<Installation>
			<InstallationTarget Id="Microsoft.VisualStudio.Code"/>
		</Installation>
		<Dependencies/>
		<Assets>
			<Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />%s%s%s
		</Assets>
	</PackageManifest>
