Before do
  @user_index = 0

  Role.truncate(cascade: true)
  Secret.truncate
  Credentials.truncate
  
  admin_role = Role.create(role_id: "cucumber:user:admin")
  Credentials.new(role: admin_role).save(raise_on_save_failure: true)
end

Before("@logged-in") do
  step %Q(I am a user named "alice")
end

Before("@logged-in-admin") do
  step %Q(I am the super-user)
end

Transform /@[\w_]+@/ do |item|
  item = item.gsub "@response_api_key@", @response_api_key if @response_api_key
  if @host_factory_token
    item = item.gsub "@host_factory_token_expiration@", @host_factory_token.expiration.iso8601
    item = item.gsub "@host_factory_token_token@", @host_factory_token.token
  end
  item
end