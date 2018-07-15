class SamlIdpController < SamlIdp::IdpController

  def create
    unless params[:email].blank? && params[:password].blank?
      user = idp_authenticate(params[:email], params[:password])
      if user.nil?
        @saml_idp_fail_msg = "Incorrect email or password."
      else
        @saml_response = idp_make_saml_response(user)

        render :template => "saml_idp/idp/saml_post", :layout => false
        return
      end
    end
    render :template => "saml_idp/idp/new"
  end

  def idp_authenticate(email, password)
    User.where(email: email).first || create_user(email)
  end

  def idp_make_saml_response(user)
    encode_SAMLResponse(user.email, {audience_uri: 'http://localhost:7000', attributes: { userID: user.id, businessID: user.business_id, profileID: user.profile_id, apiToken: SecureRandom.uuid } })
  #     , attributes_provider: %[<saml:AttributeStatement>
  #     <saml:Attribute Name="userID">
  #       <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{user.user_id}</saml:AttributeValue>
  #     </saml:Attribute>
  #     <saml:Attribute Name="businessID">
  #       <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{user.business_id}</saml:AttributeValue>
  #     </saml:Attribute>
  #     <saml:Attribute Name="profileID">
  #       <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{user.profile_id}</saml:AttributeValue>
  #     </saml:Attribute>
  #     <saml:Attribute Name="apiToken">
  #       <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{SecureRandom.uuid}</saml:AttributeValue>
  #     </saml:Attribute>
  #   </saml:AttributeStatement>]
  end

  def encode_SAMLResponse(name_id, opts = {})
    # Time configuration
    now = Time.now.utc
    not_before_delta = (Rails.env.development? ? 1000 : 5)
    not_after_delta = (Rails.env.development? ? 1000 : 180)

    # Ids and URIs
    response_id, reference_id = SecureRandom::uuid, SecureRandom::uuid
    audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
    issuer_uri = opts[:issuer_uri] || (request && request.url) || "http://example.com"

    # Additional assertion attributes
    assertion_attributes = opts[:attributes] || []
    attr_assertions = ""
    assertion_attributes.each do |key, value|
      real_value = ((value.is_a?(Hash) || value.is_a?(Array)) ? value.to_json : value)
      real_value = real_value.to_s.encode(xml: :text)
      attr_assertions += %[<Attribute Name="#{key}"><AttributeValue>#{real_value}</AttributeValue></Attribute>]
    end

    assertion = %[<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><Issuer>#{issuer_uri}</Issuer><Subject><NameID Format="urn:oasis:names:SAML:2.0:nameid-format:entity">#{name_id}</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="#{@saml_request_id}" NotOnOrAfter="#{(now+not_after_delta).iso8601}" Recipient="#{@saml_acs_url}"></SubjectConfirmationData></SubjectConfirmation></Subject><Conditions NotBefore="#{(now-not_before_delta).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><AudienceRestriction><Audience>#{audience_uri}</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="mno_uid"><AttributeValue>#{name_id}</AttributeValue></Attribute>#{attr_assertions}</AttributeStatement><AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>]

    digest_value = Base64.encode64(algorithm.digest(assertion)).delete("\n")

    signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

    signature_value = sign(signed_info).delete("\n")

    signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

    assertion_and_signature = assertion.sub(/Issuer\>\<Subject/, "Issuer>#{signature}<Subject")

    xml = %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{@saml_acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

    Base64.encode64(xml)
  end

  private

  def create_user(email)
    user = User.new(email: email)
    user.user_id = SecureRandom.uuid
    user.business_id = SecureRandom.urlsafe_base64(5)
    user.profile_id = SecureRandom.urlsafe_base64(5)
    user.save!
    user
  end
end
